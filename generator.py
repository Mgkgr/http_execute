#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Генератор одноразовых кодов (RUN_30D и DB_UPDATE).

Хранит закрытый ключ локально (base64 сырого Ed25519 ключа).
Коды подписываются Ed25519 и упаковываются как:
    base64url(payload_json) + "." + base64url(signature)

Примеры:
  # Сгенерировать пару ключей
  python generator.py gen-keys --out-dir keys

  # Сгенерировать RUN_30D код
  python generator.py run-30d --private-key keys/ed25519_private.b64

  # Сгенерировать DB_UPDATE код по файлу базы
  python generator.py db-update --private-key keys/ed25519_private.b64 \
      --db-path /path/to/accounts.sqlite --db-version 3
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


@dataclass
class KeyPair:
    private_key_b64: str
    public_key_b64: str


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64_encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _load_private_key(source: str) -> Ed25519PrivateKey:
    path = Path(source)
    if path.exists():
        key_b64 = path.read_text(encoding="utf-8").strip()
    else:
        key_b64 = source.strip()
    raw = base64.b64decode(key_b64)
    return Ed25519PrivateKey.from_private_bytes(raw)


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_payload(
    *,
    code_type: str,
    serial: str,
    issued_at_utc: str,
    duration_days: Optional[int] = None,
    db_plain_sha256: Optional[str] = None,
    db_version: Optional[int] = None,
    machine: Optional[str] = None,
    not_before_utc: Optional[str] = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": code_type,
        "serial": serial,
        "issued_at_utc": issued_at_utc,
    }
    if duration_days is not None:
        payload["duration_days"] = duration_days
    if db_plain_sha256 is not None:
        payload["db_plain_sha256"] = db_plain_sha256
    if db_version is not None:
        payload["db_version"] = db_version
    if machine:
        payload["machine"] = machine
    if not_before_utc:
        payload["not_before_utc"] = not_before_utc
    return payload


def _sign_payload(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    signature = private_key.sign(payload_bytes)
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(signature)}"


def _write_log(path: Path, entry: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _keypair_from_private(private_key: Ed25519PrivateKey) -> KeyPair:
    private_raw = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return KeyPair(private_key_b64=_b64_encode(private_raw), public_key_b64=_b64_encode(public_raw))


def _gen_keys(args: argparse.Namespace) -> int:
    private_key = Ed25519PrivateKey.generate()
    pair = _keypair_from_private(private_key)

    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "ed25519_private.b64").write_text(pair.private_key_b64 + "\n", encoding="utf-8")
        (out_dir / "ed25519_public.b64").write_text(pair.public_key_b64 + "\n", encoding="utf-8")

    print("PRIVATE_KEY_B64:", pair.private_key_b64)
    print("PUBLIC_KEY_B64:", pair.public_key_b64)
    return 0


def _run_30d(args: argparse.Namespace) -> int:
    private_key = _load_private_key(args.private_key)
    serial = args.serial or str(uuid.uuid4())
    issued_at = _utc_now_iso()
    payload = _build_payload(
        code_type="RUN_30D",
        serial=serial,
        issued_at_utc=issued_at,
        duration_days=args.duration_days,
        machine=args.machine,
        not_before_utc=args.not_before_utc,
    )
    code = _sign_payload(payload, private_key)
    print(code)

    if args.log:
        _write_log(
            Path(args.log),
            {
                "type": payload["type"],
                "serial": serial,
                "issued_at_utc": issued_at,
                "payload": payload,
                "code": code,
            },
        )
    return 0


def _db_update(args: argparse.Namespace) -> int:
    private_key = _load_private_key(args.private_key)
    serial = args.serial or str(uuid.uuid4())
    issued_at = _utc_now_iso()

    db_sha = args.db_sha256
    if args.db_path:
        db_sha = _sha256_file(Path(args.db_path))

    if not db_sha or not args.db_version:
        print("Нужны --db-version и (--db-sha256 или --db-path).", file=sys.stderr)
        return 2

    payload = _build_payload(
        code_type="DB_UPDATE",
        serial=serial,
        issued_at_utc=issued_at,
        db_plain_sha256=db_sha,
        db_version=int(args.db_version),
        machine=args.machine,
        not_before_utc=args.not_before_utc,
    )
    code = _sign_payload(payload, private_key)
    print(code)

    if args.log:
        _write_log(
            Path(args.log),
            {
                "type": payload["type"],
                "serial": serial,
                "issued_at_utc": issued_at,
                "payload": payload,
                "code": code,
            },
        )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Генератор одноразовых кодов")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keys_parser = subparsers.add_parser("gen-keys", help="Сгенерировать пару Ed25519 ключей")
    keys_parser.add_argument("--out-dir", help="Каталог для сохранения ключей")
    keys_parser.set_defaults(func=_gen_keys)

    run_parser = subparsers.add_parser("run-30d", help="Сгенерировать RUN_30D код")
    run_parser.add_argument("--private-key", required=True, help="Путь к приватному ключу (base64) или строка")
    run_parser.add_argument("--duration-days", type=int, default=30, help="Срок действия в днях")
    run_parser.add_argument("--serial", help="Серийный номер (если не задан, будет UUID)")
    run_parser.add_argument("--machine", help="Machine ID для привязки (опционально)")
    run_parser.add_argument("--not-before-utc", help="Не ранее этой даты (ISO, UTC)")
    run_parser.add_argument("--log", default="codes.log.jsonl", help="Файл журнала выдачи")
    run_parser.set_defaults(func=_run_30d)

    db_parser = subparsers.add_parser("db-update", help="Сгенерировать DB_UPDATE код")
    db_parser.add_argument("--private-key", required=True, help="Путь к приватному ключу (base64) или строка")
    db_parser.add_argument("--db-path", help="Путь к plaintext SQLite базе (для вычисления sha256)")
    db_parser.add_argument("--db-sha256", help="SHA256 plaintext базы (если не используешь --db-path)")
    db_parser.add_argument("--db-version", type=int, required=True, help="Версия базы (строго возрастает)")
    db_parser.add_argument("--serial", help="Серийный номер (если не задан, будет UUID)")
    db_parser.add_argument("--machine", help="Machine ID для привязки (опционально)")
    db_parser.add_argument("--not-before-utc", help="Не ранее этой даты (ISO, UTC)")
    db_parser.add_argument("--log", default="codes.log.jsonl", help="Файл журнала выдачи")
    db_parser.set_defaults(func=_db_update)

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
