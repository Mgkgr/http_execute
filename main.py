# -*- coding: utf-8 -*-
"""
Автономное приложение-обёртка над http_complex_control_execute:
- Проверка доверенного времени по сети на старте (NTP + HTTPS Date)
- Одноразовые коды: RUN_30D (работа 30 суток) и DB_UPDATE (однократный импорт базы)
- Защита базы: хранение в зашифрованном виде + контроль sha256(ciphertext)
- Защищённое состояние (expiry, used serials, last trusted time, db_version, db_hash)

Запуск:
  python -m rice.apps.http_cc_standalone_app

Интеграция:
  использует export_data_for_all_users_http(...) из rice.modules.http_complex_control_execute
  :contentReference[oaicite:1]{index=1}
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import dataclasses
import email.utils
import hashlib
import json
import os
import platform
import secrets
import socket
import sqlite3
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests

try:
    # Ed25519 + AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as exc:
    raise RuntimeError(
        "Нужна зависимость 'cryptography' (pip install cryptography)."
    ) from exc


# ---------------------------
# НАСТРОЙКИ / КОНСТАНТЫ
# ---------------------------

APP_NAME = "RiceHttpCCStandalone"
STATE_FILE = "state.dpapi.bin"
STATE_SHADOW_FILE = "state.shadow.dpapi.bin"
DB_CIPHER_FILE = "accounts.db.aesgcm"

# Публичный ключ Ed25519 (32 байта) в base64.
# Сгенерируешь в генераторе кодов и вставишь сюда.
PUBLIC_KEY_B64 = "PASTE_YOUR_ED25519_PUBLIC_KEY_BASE64_HERE"

# Источники времени
NTP_SERVERS = [
    ("time.google.com", 123),
    ("time.cloudflare.com", 123),
    ("pool.ntp.org", 123),
]
HTTPS_DATE_URLS = [
    "https://www.google.com",
    "https://www.cloudflare.com",
    "https://www.microsoft.com",
]

TIME_SKEW_ALLOW_SEC = 300  # допустимое расхождение источников (5 минут)
ANTI_ROLLBACK_SKEW_SEC = 120  # допускаем 2 минуты назад (часы чуть "пляшут")
RUN_DAYS_DEFAULT = 30

# Для DB_UPDATE — сколько держим "окно" импорта после ввода кода
DB_UPDATE_WINDOW_MIN = 60


# ---------------------------
# ВСПОМОГАТЕЛЬНОЕ
# ---------------------------

def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _app_data_dir() -> Path:
    # user-local, чтобы DPAPI CurrentUser было логично
    if os.name == "nt":
        base = os.getenv("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME
    # linux/mac
    base = os.getenv("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP_NAME


def _machine_fingerprint() -> str:
    """
    Стабильный отпечаток машины/установки.
    Не "суперсекретный", но достаточно для привязки лицензий.
    """
    parts: list[str] = []
    parts.append(platform.system())
    parts.append(platform.release())
    parts.append(platform.node())
    parts.append(hex(uuid.getnode()))

    if os.name == "nt":
        try:
            import winreg  # type: ignore
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography"
            ) as k:
                val, _ = winreg.QueryValueEx(k, "MachineGuid")
                parts.append(str(val))
        except Exception:
            pass
    else:
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                if os.path.exists(p):
                    parts.append(Path(p).read_text(encoding="utf-8", errors="ignore").strip())
                    break
            except Exception:
                pass

    raw = "|".join(parts).encode("utf-8", "ignore")
    return hashlib.sha256(raw).hexdigest()


# ---------------------------
# TRUSTED TIME (NTP + HTTPS Date)
# ---------------------------

class TrustedTimeError(RuntimeError):
    pass


def _sntp_query(host: str, port: int, timeout: float = 2.0) -> Optional[datetime]:
    """
    Простой SNTP запрос (без NTS).
    Возвращает UTC-время или None.
    """
    try:
        addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][4]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            # NTP packet: LI=0, VN=3, Mode=3 (client) => 0x1B
            msg = b"\x1b" + 47 * b"\0"
            sock.sendto(msg, addr)
            data, _ = sock.recvfrom(48)
            if len(data) < 48:
                return None

            # Transmit Timestamp starts at byte 40
            # NTP epoch starts 1900-01-01
            sec = int.from_bytes(data[40:44], "big")
            frac = int.from_bytes(data[44:48], "big")
            ntp_time = sec + frac / 2**32
            unix_time = ntp_time - 2208988800  # 1900->1970
            return datetime.fromtimestamp(unix_time, tz=timezone.utc)
        finally:
            sock.close()
    except Exception:
        return None


def _https_date_query(url: str, timeout: float = 3.0) -> Optional[datetime]:
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        date_hdr = r.headers.get("Date")
        if not date_hdr:
            # иногда HEAD режут, попробуем GET маленький
            r = requests.get(url, timeout=timeout, stream=True)
            date_hdr = r.headers.get("Date")
        if not date_hdr:
            return None
        dt = email.utils.parsedate_to_datetime(date_hdr)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def get_trusted_time_utc() -> datetime:
    """
    Получаем доверенное время.
    Требование: сеть обязательна. Если не смогли — падаем.
    """
    samples: list[datetime] = []

    # NTP
    for host, port in NTP_SERVERS:
        t = _sntp_query(host, port)
        if t:
            samples.append(t)

    # HTTPS Date
    for url in HTTPS_DATE_URLS:
        t = _https_date_query(url)
        if t:
            samples.append(t)

    if not samples:
        raise TrustedTimeError("Не удалось получить время по сети (нет NTP/HTTPS Date).")

    # Если есть несколько источников — проверим согласованность и возьмём медиану
    samples.sort()
    if len(samples) >= 2:
        spread = (samples[-1] - samples[0]).total_seconds()
        if spread > TIME_SKEW_ALLOW_SEC:
            raise TrustedTimeError(
                f"Источники времени сильно расходятся (разброс ~{int(spread)} сек)."
            )
        mid = samples[len(samples) // 2]
        return mid

    return samples[0]


# ---------------------------
# DPAPI (Windows) / Fallback store
# ---------------------------

class SecureStoreError(RuntimeError):
    pass


class _DPAPI:
    """
    DPAPI CurrentUser encrypt/decrypt.
    """

    CRYPTPROTECT_UI_FORBIDDEN = 0x01

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    @staticmethod
    def _blob_from_bytes(data: bytes) -> "_DPAPI.DATA_BLOB":
        buf = (ctypes.c_byte * len(data)).from_buffer_copy(data)
        return _DPAPI.DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

    @staticmethod
    def protect(data: bytes, entropy: bytes = b"") -> bytes:
        if os.name != "nt":
            raise SecureStoreError("DPAPI доступен только на Windows.")

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_blob = _DPAPI._blob_from_bytes(data)
        entropy_blob = _DPAPI._blob_from_bytes(entropy) if entropy else None
        out_blob = _DPAPI.DATA_BLOB()

        res = crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            ctypes.c_wchar_p(""),
            ctypes.byref(entropy_blob) if entropy_blob else None,
            None,
            None,
            _DPAPI.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        if not res:
            raise SecureStoreError("CryptProtectData failed.")

        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return out
        finally:
            kernel32.LocalFree(out_blob.pbData)

    @staticmethod
    def unprotect(data: bytes, entropy: bytes = b"") -> bytes:
        if os.name != "nt":
            raise SecureStoreError("DPAPI доступен только на Windows.")

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_blob = _DPAPI._blob_from_bytes(data)
        entropy_blob = _DPAPI._blob_from_bytes(entropy) if entropy else None
        out_blob = _DPAPI.DATA_BLOB()

        res = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(entropy_blob) if entropy_blob else None,
            None,
            None,
            _DPAPI.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        if not res:
            raise SecureStoreError("CryptUnprotectData failed (возможно другой пользователь/профиль).")

        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return out
        finally:
            kernel32.LocalFree(out_blob.pbData)


def _entropy_bytes() -> bytes:
    # привязка к приложению + отпечаток машины
    return (APP_NAME + "|" + _machine_fingerprint()).encode("utf-8")


# ---------------------------
# STATE
# ---------------------------

@dataclass
class PendingDbUpdate:
    allowed_plain_sha256: str
    target_db_version: int
    issued_at_utc: str  # ISO
    expires_at_utc: str  # ISO


@dataclass
class AppState:
    # лицензия
    expiry_utc: Optional[str] = None  # ISO
    last_trusted_utc: Optional[str] = None  # ISO

    # одноразовость
    used_serial_hashes: list[str] = dataclasses.field(default_factory=list)

    # база
    db_key_b64: Optional[str] = None  # 32 bytes key for AESGCM
    db_cipher_sha256: Optional[str] = None
    last_db_version: int = 0

    pending_db_update: Optional[PendingDbUpdate] = None

    # служебное
    machine_id: Optional[str] = None
    schema: int = 1


class SecureStateStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.path = root / STATE_FILE
        self.shadow_path = root / STATE_SHADOW_FILE

    def load(self) -> AppState:
        a = self._load_one(self.path)
        b = self._load_one(self.shadow_path)
        if a and b:
            # если расходятся — берём "более новый" по last_trusted_utc и делаем merge критичных полей
            merged = self._merge(a, b)
            self.save(merged)
            return merged
        if a:
            self.save(a)  # восстановим shadow
            return a
        if b:
            self.save(b)  # восстановим primary
            return b

        st = AppState(machine_id=_machine_fingerprint())
        self.save(st)
        return st

    def save(self, state: AppState) -> None:
        raw = json.dumps(dataclasses.asdict(state), ensure_ascii=False, sort_keys=True).encode("utf-8")
        enc = self._encrypt(raw)
        _atomic_write_bytes(self.path, enc)
        _atomic_write_bytes(self.shadow_path, enc)

    def _merge(self, a: AppState, b: AppState) -> AppState:
        def parse_iso(x: Optional[str]) -> Optional[datetime]:
            if not x:
                return None
            return datetime.fromisoformat(x)

        la = parse_iso(a.last_trusted_utc)
        lb = parse_iso(b.last_trusted_utc)

        # базово берём "новее"
        base = a if (la or datetime.min.replace(tzinfo=timezone.utc)) >= (lb or datetime.min.replace(tzinfo=timezone.utc)) else b
        other = b if base is a else a

        # merge used serials (union)
        used = set(base.used_serial_hashes) | set(other.used_serial_hashes)

        # expiry берём максимум
        ea = parse_iso(base.expiry_utc)
        eb = parse_iso(other.expiry_utc)
        expiry = max([d for d in [ea, eb] if d], default=None)

        # last_db_version берём максимум
        dbv = max(base.last_db_version, other.last_db_version)

        # db_cipher_sha256: если совпадает — ок, иначе оставляем от base (а несовпадение будет поймано при проверке БД)
        out = dataclasses.replace(
            base,
            used_serial_hashes=sorted(list(used)),
            expiry_utc=expiry.isoformat() if expiry else None,
            last_db_version=dbv,
        )
        if not out.machine_id:
            out.machine_id = _machine_fingerprint()
        return out

    def _encrypt(self, raw: bytes) -> bytes:
        entropy = _entropy_bytes()
        if os.name == "nt":
            return _DPAPI.protect(raw, entropy=entropy)
        # fallback: AESGCM с ключом от machine_fingerprint (хуже, но лучше чем plaintext)
        k = hashlib.sha256(entropy).digest()
        aes = AESGCM(k)
        nonce = secrets.token_bytes(12)
        ct = aes.encrypt(nonce, raw, b"state")
        return b"AESGCM1" + nonce + ct

    def _decrypt(self, enc: bytes) -> bytes:
        entropy = _entropy_bytes()
        if os.name == "nt":
            return _DPAPI.unprotect(enc, entropy=entropy)
        if enc.startswith(b"AESGCM1") and len(enc) > 7 + 12:
            nonce = enc[7:19]
            ct = enc[19:]
            k = hashlib.sha256(entropy).digest()
            aes = AESGCM(k)
            return aes.decrypt(nonce, ct, b"state")
        raise SecureStoreError("Неизвестный формат state.")

    def _load_one(self, path: Path) -> Optional[AppState]:
        try:
            if not path.exists():
                return None
            enc = path.read_bytes()
            raw = self._decrypt(enc)
            data = json.loads(raw.decode("utf-8"))
            # pending_db_update вручную восстановим
            p = data.get("pending_db_update")
            if p:
                data["pending_db_update"] = PendingDbUpdate(**p)
            return AppState(**data)
        except Exception:
            return None


# ---------------------------
# LICENSE TOKENS (Ed25519 signed payload)
# ---------------------------

class LicenseError(RuntimeError):
    pass


class LicenseManager:
    def __init__(self, pubkey_b64: str, state_store: SecureStateStore) -> None:
        self.pubkey = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
        self.store = state_store

    def is_active(self, state: AppState, trusted_now: datetime) -> bool:
        if not state.expiry_utc:
            return False
        exp = datetime.fromisoformat(state.expiry_utc)
        return trusted_now <= exp

    def apply_code(self, state: AppState, trusted_now: datetime, code: str) -> AppState:
        payload = self._verify_and_parse(code)

        # одноразовость
        serial = str(payload.get("serial", "")).strip()
        if not serial:
            raise LicenseError("В коде нет serial.")
        serial_hash = hashlib.sha256(serial.encode("utf-8")).hexdigest()
        if serial_hash in set(state.used_serial_hashes):
            raise LicenseError("Этот код уже использован.")

        # привязка к машине (если есть)
        machine = payload.get("machine")
        if machine:
            current = _machine_fingerprint()
            if str(machine).strip().lower() != current.lower():
                raise LicenseError("Код привязан к другой машине.")

        typ = str(payload.get("type", "")).strip().upper()
        if typ not in ("RUN_30D", "DB_UPDATE"):
            raise LicenseError("Неизвестный тип кода.")

        # not before (опционально)
        nb = payload.get("not_before_utc")
        if nb:
            nb_dt = datetime.fromisoformat(nb)
            if trusted_now < nb_dt:
                raise LicenseError("Код ещё нельзя применять (not_before).")

        # применяем
        used = set(state.used_serial_hashes)
        used.add(serial_hash)
        state.used_serial_hashes = sorted(list(used))

        if typ == "RUN_30D":
            days = int(payload.get("duration_days", RUN_DAYS_DEFAULT))
            base_dt = trusted_now
            if state.expiry_utc:
                old_exp = datetime.fromisoformat(state.expiry_utc)
                if old_exp > base_dt:
                    base_dt = old_exp
            new_exp = base_dt + timedelta(days=days)
            state.expiry_utc = new_exp.isoformat()

        elif typ == "DB_UPDATE":
            db_sha = str(payload.get("db_plain_sha256", "")).strip().lower()
            db_ver = int(payload.get("db_version", 0))
            if not db_sha or db_ver <= 0:
                raise LicenseError("DB_UPDATE код должен содержать db_plain_sha256 и db_version>0.")
            if db_ver <= state.last_db_version:
                raise LicenseError("db_version в коде должен быть больше текущей (anti-rollback).")

            issued = trusted_now
            expires = trusted_now + timedelta(minutes=DB_UPDATE_WINDOW_MIN)
            state.pending_db_update = PendingDbUpdate(
                allowed_plain_sha256=db_sha,
                target_db_version=db_ver,
                issued_at_utc=issued.isoformat(),
                expires_at_utc=expires.isoformat(),
            )

        return state

    def _verify_and_parse(self, code: str) -> dict[str, Any]:
        """
        Формат кода:
          base64url(payload_json_bytes) + "." + base64url(signature_bytes)
        где signature = Ed25519.sign(payload_bytes)
        """
        code = code.strip()
        if "." not in code:
            raise LicenseError("Неверный формат кода (нет точки).")
        p1, p2 = code.split(".", 1)
        payload_bytes = _b64url_decode(p1)
        sig = _b64url_decode(p2)

        try:
            self.pubkey.verify(sig, payload_bytes)
        except Exception as exc:
            raise LicenseError("Подпись кода не прошла проверку.") from exc

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("payload не dict")
            return payload
        except Exception as exc:
            raise LicenseError("payload не JSON.") from exc


# ---------------------------
# ENCRYPTED ACCOUNTS DB
# ---------------------------

class DbError(RuntimeError):
    pass


class AccountsDb:
    def __init__(self, root: Path, store: SecureStateStore) -> None:
        self.root = root
        self.store = store
        self.db_cipher_path = root / DB_CIPHER_FILE

    def ensure_ready(self, state: AppState) -> AppState:
        if not state.db_key_b64:
            key = secrets.token_bytes(32)
            state.db_key_b64 = base64.b64encode(key).decode("ascii")

        if not self.db_cipher_path.exists():
            # создадим пустую базу accounts и зашифруем
            plain = self._create_empty_plain_db()
            try:
                self._encrypt_and_write(state, plain)
                state.db_cipher_sha256 = _sha256_file(self.db_cipher_path)
                state.last_db_version = max(state.last_db_version, 1)
            finally:
                try:
                    os.remove(plain)
                except OSError:
                    pass
        else:
            # защита от подмены: сверим sha256(cipher)
            cur = _sha256_file(self.db_cipher_path)
            if state.db_cipher_sha256 and cur != state.db_cipher_sha256:
                raise DbError("Обнаружена подмена/замена зашифрованной базы (sha256 не совпадает).")

        return state

    def load_accounts(self, state: AppState) -> list[tuple[str, str]]:
        # дешифруем во временный файл, читаем, удаляем
        with self._decrypted_temp_db(state) as temp_db_path:
            return self._read_accounts(temp_db_path)

    def import_plain_db(self, state: AppState, plain_db_path: Path) -> AppState:
        # нужен pending_db_update
        pend = state.pending_db_update
        if not pend:
            raise DbError("Нет разрешения на импорт. Нужен DB_UPDATE код.")
        now = _now_utc()
        exp = datetime.fromisoformat(pend.expires_at_utc)
        if now > exp:
            state.pending_db_update = None
            raise DbError("Окно импорта истекло. Введи новый DB_UPDATE код.")

        # проверка sha256 (plain)
        actual = _sha256_file(plain_db_path).lower()
        if actual != pend.allowed_plain_sha256.lower():
            raise DbError("SHA256 базы не совпал с тем, что разрешено кодом.")

        # минимальная валидация sqlite
        self._validate_plain_db(plain_db_path)

        # encrypt + write
        self._encrypt_and_write(state, str(plain_db_path))

        # обновим state
        state.db_cipher_sha256 = _sha256_file(self.db_cipher_path)
        state.last_db_version = pend.target_db_version
        state.pending_db_update = None
        return state

    def _key(self, state: AppState) -> bytes:
        if not state.db_key_b64:
            raise DbError("Нет ключа БД.")
        return base64.b64decode(state.db_key_b64)

    def _encrypt_and_write(self, state: AppState, plain_db_path: str) -> None:
        key = self._key(state)
        aes = AESGCM(key)
        nonce = secrets.token_bytes(12)
        plain = Path(plain_db_path).read_bytes()
        ct = aes.encrypt(nonce, plain, b"accounts-db")
        blob = b"AESGCM1" + nonce + ct
        _atomic_write_bytes(self.db_cipher_path, blob)

    def _decrypt_to_bytes(self, state: AppState) -> bytes:
        data = self.db_cipher_path.read_bytes()
        if not data.startswith(b"AESGCM1") or len(data) <= 7 + 12:
            raise DbError("Неверный формат зашифрованной БД.")
        nonce = data[7:19]
        ct = data[19:]
        key = self._key(state)
        aes = AESGCM(key)
        try:
            return aes.decrypt(nonce, ct, b"accounts-db")
        except Exception as exc:
            raise DbError("Не удалось расшифровать БД (возможно подмена/повреждение).") from exc

    def _create_empty_plain_db(self) -> str:
        fd, path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        with sqlite3.connect(path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS accounts (username TEXT PRIMARY KEY, password TEXT NOT NULL)"
            )
            conn.commit()
        return path

    def _validate_plain_db(self, path: Path) -> None:
        try:
            with sqlite3.connect(str(path)) as conn:
                conn.execute("SELECT username, password FROM accounts LIMIT 1")
        except Exception as exc:
            raise DbError("Импортируемая база невалидна (нет таблицы accounts?).") from exc

    def _read_accounts(self, path: Path) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        with sqlite3.connect(str(path)) as conn:
            cur = conn.execute("SELECT username, password FROM accounts")
            for u, p in cur.fetchall():
                out.append((str(u), str(p)))
        return out

    class _TempCtx:
        def __init__(self, tmp_path: Path) -> None:
            self.tmp_path = tmp_path

        def __enter__(self) -> Path:
            return self.tmp_path

        def __exit__(self, exc_type, exc, tb) -> None:
            try:
                os.remove(self.tmp_path)
            except OSError:
                pass

    def _decrypted_temp_db(self, state: AppState) -> "_TempCtx":
        plain = self._decrypt_to_bytes(state)
        fd, tmp = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        tmp_path = Path(tmp)
        tmp_path.write_bytes(plain)
        return self._TempCtx(tmp_path)


# ---------------------------
# OTP provider (interactive)
# ---------------------------

def otp_provider_interactive(username: str) -> str:
    return input(f"Введите OTP для пользователя {username}: ").strip()


# ---------------------------
# MAIN EXECUTION
# ---------------------------

def _configure_logging() -> None:
    try:
        from rice.logging_setup import configure_logging  # type: ignore
        configure_logging()
    except Exception:
        import logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )


def _run_export(accounts: list[tuple[str, str]]) -> None:
    # импортируем здесь, чтобы при проблемах с лицензией лишний раз не грузить модули
    from rice.modules.http_complex_control_execute import export_data_for_all_users_http  # :contentReference[oaicite:2]{index=2}

    output = input("Путь сохранения xlsx (Enter = спросит диалог/консоль внутри модуля): ").strip() or None
    export_data_for_all_users_http(
        output_path=output,
        accounts=accounts,
        otp_provider=otp_provider_interactive,
    )


def main() -> None:
    _configure_logging()
    root = _app_data_dir()
    store = SecureStateStore(root)
    state = store.load()

    # Зафиксируем machine_id при первом старте
    if not state.machine_id:
        state.machine_id = _machine_fingerprint()

    # 1) Требование: сеть + проверка времени на старте
    print("Проверяю время по сети...")
    trusted_now = get_trusted_time_utc()
    print("Доверенное время (UTC):", trusted_now.isoformat())

    # anti-rollback по last_trusted_utc
    if state.last_trusted_utc:
        last = datetime.fromisoformat(state.last_trusted_utc)
        if trusted_now < last - timedelta(seconds=ANTI_ROLLBACK_SKEW_SEC):
            raise TrustedTimeError("Время 'откатилось' назад относительно сохранённого trusted-time.")

    state.last_trusted_utc = trusted_now.isoformat()

    # 2) Подготовка БД (и контроль подмены)
    accounts_db = AccountsDb(root, store)
    state = accounts_db.ensure_ready(state)

    # 3) Лицензия
    if PUBLIC_KEY_B64.startswith("PASTE_"):
        print("\n[!] Не задан PUBLIC_KEY_B64. Вставь публичный ключ Ed25519 в код.\n")
        sys.exit(2)

    lic = LicenseManager(PUBLIC_KEY_B64, store)

    def ensure_license() -> AppState:
        nonlocal state, trusted_now
        if lic.is_active(state, trusted_now):
            return state
        print("\nЛицензия не активна или истекла.")
        code = input("Введи код RUN_30D: ").strip()
        state = lic.apply_code(state, trusted_now, code)
        store.save(state)
        if not lic.is_active(state, trusted_now):
            raise LicenseError("Код применён, но лицензия всё равно не активна.")
        return state

    # 4) Меню
    while True:
        store.save(state)

        exp = state.expiry_utc or "—"
        print("\n==============================")
        print("Rice HTTP CC Standalone")
        print("Машина:", state.machine_id[:12] if state.machine_id else "—")
        print("Лицензия до (UTC):", exp)
        print("Версия базы:", state.last_db_version)
        print("==============================")
        print("1) Запустить экспорт (HTTP)")
        print("2) Ввести код (RUN_30D или DB_UPDATE)")
        print("3) Импорт базы (требует DB_UPDATE код)")
        print("4) Показать статус / обновить trusted-time сейчас")
        print("0) Выход")
        choice = input("> ").strip()

        if choice == "0":
            break

        if choice == "4":
            print("Обновляю доверенное время...")
            trusted_now = get_trusted_time_utc()
            print("Доверенное время (UTC):", trusted_now.isoformat())
            state.last_trusted_utc = trusted_now.isoformat()
            store.save(state)
            continue

        if choice == "2":
            code = input("Введи код: ").strip()
            state = lic.apply_code(state, trusted_now, code)
            store.save(state)
            print("Код принят.")
            continue

        if choice == "3":
            # разрешение должно быть в pending_db_update
            p = state.pending_db_update
            if not p:
                print("Нет активного разрешения. Введи DB_UPDATE код (пункт 2).")
                continue
            print(f"Разрешён импорт базы sha256={p.allowed_plain_sha256[:12]}.. версия={p.target_db_version}")
            path = input("Путь к SQLITE базе (plaintext) для импорта: ").strip()
            if not path:
                continue
            state = accounts_db.import_plain_db(state, Path(path))
            store.save(state)
            print("База обновлена.")
            continue

        if choice == "1":
            # для работы — нужна активная лицензия
            state = ensure_license()

            # перед запуском ещё раз проверим подмену cipher-db
            state = accounts_db.ensure_ready(state)
            store.save(state)

            accounts = accounts_db.load_accounts(state)
            if not accounts:
                print("В базе нет аккаунтов. Импортируй базу через DB_UPDATE код (пункт 3).")
                continue

            _run_export(accounts)
            print("Готово.")
            continue

        print("Не понял пункт меню.")

    store.save(state)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("\n[ОШИБКА]", e)
        raise
