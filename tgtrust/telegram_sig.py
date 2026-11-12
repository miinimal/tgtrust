"""Verification of Telegram Mini App init data signed with Telegram's Ed25519 key.

Telegram signs the init data passed to a Mini App so that third parties can
check it without knowing the bot token (Bot API 8.0, November 2024).
Reference: https://core.telegram.org/bots/webapps#validating-data-for-third-party-use

Data-check-string: "<bot_id>:WebAppData\\n" followed by every received field
except ``hash`` and ``signature``, as ``key=value`` pairs sorted by key and
joined with line feeds. The ``signature`` field is the base64url-encoded
Ed25519 signature of that string.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Public keys published by Telegram for third-party validation (hex).
TELEGRAM_PUBLIC_KEYS: dict[str, str] = {
    "production": "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d",
    "test": "40055058a4ee38156a06562e52eece92a771bcd8346a8c4615cb7376eddf72ec",
}

# Tolerated clock skew for auth_date values slightly in the future (seconds).
FUTURE_SKEW_SECONDS = 60

_EXCLUDED_FIELDS = ("hash", "signature")


class InitDataError(Exception):
    """Raised when init data is malformed, forged, stale or otherwise unusable."""


@dataclass(frozen=True)
class VerifiedInitData:
    """Init data whose Telegram signature has been verified."""

    bot_id: int
    auth_date: int
    user: dict
    fields: dict = field(repr=False)

    @property
    def user_id(self) -> int:
        return int(self.user["id"])

    @property
    def is_premium(self) -> bool:
        return bool(self.user.get("is_premium"))

    @property
    def is_bot(self) -> bool:
        return bool(self.user.get("is_bot"))


def data_check_string(bot_id: int, fields: dict[str, str]) -> str:
    """Build the exact string Telegram signs for third-party validation."""
    pairs = sorted((k, v) for k, v in fields.items() if k not in _EXCLUDED_FIELDS)
    body = "\n".join(f"{k}={v}" for k, v in pairs)
    return f"{bot_id}:WebAppData\n{body}"


def _b64url_decode(value: str) -> bytes:
    # Some Telegram clients omit base64 padding.
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise InitDataError("signature is not valid base64url") from exc


def _parse_fields(init_data: str) -> dict[str, str]:
    try:
        pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise InitDataError("init data is not a valid query string") from exc
    fields: dict[str, str] = {}
    for key, value in pairs:
        if key in fields:
            raise InitDataError(f"duplicate field: {key}")
        fields[key] = value
    return fields


def _load_public_key(environment: str, public_key_hex: str | None) -> Ed25519PublicKey:
    key_hex = public_key_hex or TELEGRAM_PUBLIC_KEYS.get(environment)
    if key_hex is None:
        raise ValueError(f"unknown environment: {environment}")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))


def verify_init_data(
    init_data: str,
    bot_id: int,
    *,
    environment: str = "production",
    public_key_hex: str | None = None,
    max_age_seconds: int = 900,
    now: int | None = None,
) -> VerifiedInitData:
    """Verify Telegram's Ed25519 signature over Mini App init data.

    ``public_key_hex`` overrides the published key (used in tests only).
    Raises :class:`InitDataError` on any failure; never returns unverified data.
    """
    fields = _parse_fields(init_data)

    signature_b64 = fields.get("signature")
    if not signature_b64:
        raise InitDataError("signature field is missing")
    signature = _b64url_decode(signature_b64)
    if len(signature) != 64:
        raise InitDataError("signature has wrong length")

    public_key = _load_public_key(environment, public_key_hex)
    message = data_check_string(bot_id, fields).encode("utf-8")
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise InitDataError("signature does not match") from exc

    try:
        auth_date = int(fields["auth_date"])
    except (KeyError, ValueError) as exc:
        raise InitDataError("auth_date is missing or invalid") from exc

    current = int(time.time()) if now is None else now
    if auth_date > current + FUTURE_SKEW_SECONDS:
        raise InitDataError("auth_date is in the future")
    if current - auth_date > max_age_seconds:
        raise InitDataError("init data has expired")

    raw_user = fields.get("user")
    if not raw_user:
        raise InitDataError("user field is missing")
    try:
        user = json.loads(raw_user)
    except json.JSONDecodeError as exc:
        raise InitDataError("user field is not valid JSON") from exc
    if not isinstance(user, dict) or not isinstance(user.get("id"), int):
        raise InitDataError("user id is missing")

    return VerifiedInitData(bot_id=bot_id, auth_date=auth_date, user=user, fields=fields)


def _cli(argv: list[str] | None = None, *, public_key_hex: str | None = None, now: int | None = None) -> int:
    """Check one real init data string. Prints one line; never the user id, name or raw string.

    ``public_key_hex`` and ``now`` exist for tests only; the command line always uses the published key."""
    import argparse
    from datetime import datetime, timezone

    parser = argparse.ArgumentParser(
        prog="python -m tgtrust.telegram_sig",
        allow_abbrev=False,
        description="Verify Mini App init data (read from a file) with Telegram's published key.",
    )
    parser.add_argument("--init-data-file", required=True, help="file holding the init data string")
    parser.add_argument("--bot-id", required=True, type=int)
    parser.add_argument("--env", choices=sorted(TELEGRAM_PUBLIC_KEYS), default="production")
    parser.add_argument("--max-age", type=int, default=900, metavar="SECONDS")
    args = parser.parse_args(argv)

    try:
        with open(args.init_data_file, encoding="utf-8") as fh:
            raw = fh.read().strip()
    except (OSError, UnicodeDecodeError) as exc:
        print(f"INVALID: cannot read init data file ({type(exc).__name__})")
        return 1
    if not raw:
        print("INVALID: init data file is empty")
        return 1
    try:
        verified = verify_init_data(
            raw, args.bot_id, environment=args.env, max_age_seconds=args.max_age,
            public_key_hex=public_key_hex, now=now,
        )
    except InitDataError as exc:
        print(f"INVALID: {exc}")
        return 1
    stamp = datetime.fromtimestamp(verified.auth_date, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    age = (int(time.time()) if now is None else now) - verified.auth_date
    print(f"VALID: user id present, auth_date {stamp}, age {age} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
