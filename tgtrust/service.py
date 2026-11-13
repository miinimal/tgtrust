"""HTTP service for credential issuance and verification.

Endpoints (JSON, binary values in unpadded base64url):
  GET  /v1/health   liveness probe
  GET  /v1/issuer   issuer public key, key id, scheme and policy
  POST /v1/issue    {init_data, blinded_message} -> {blind_signature, key_id}
  POST /v1/verify   {token, signature} -> {valid, key_id}
  POST /v1/challenge                 -> {challenge}
  POST /v1/register {token, signature, agent_public_key, salt, challenge, agent_signature} -> badge
  GET  /v1/agents/{agent_public_key_hex} -> badge, 404 if unknown
  GET  /app/        the holder Mini App (static files from tgtrust/webapp, same origin as the API)

Configuration comes only from environment variables (see ``Settings.from_env``);
no secret is ever read from a request or written to logs.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import threading
import time
from collections import defaultdict, deque
import pathlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Path, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from .issuer import (
    CREDENTIAL_PREFIX,
    Credential,
    Issuer,
    IssuanceError,
    IssuerPolicy,
    SqliteIssuedStore,
    verify_credential,
)
from .badge import StakeSource, build_badge
from .deals import DealError, DealLedger
from .disputes import DisputeBook, DisputeError
from .stake import StakeLookupError, StakeReader
from .registry import Registry, RegistrationError

_REGISTRATION_STATUS = {
    "invalid_request": 400,
    "token_mismatch": 403,
    "invalid_credential": 403,
    "invalid_agent_signature": 403,
    "invalid_challenge": 403,
    "already_registered": 409,
}

SCHEME = "RSABSSA-SHA384-PSSZERO-Deterministic"
MAX_BODY_BYTES = 16 * 1024
MAX_CASE_ID = 2**63 - 1  # case ids are 63-bit (SQLite INTEGER); anything larger cannot exist

# The holder Mini App. Only these files are served, by exact name, from inside the package.
WEBAPP_DIR = pathlib.Path(__file__).resolve().parent / "webapp"
WEBAPP_FILES = {
    "holder.html": "text/html; charset=utf-8",
    "holder.css": "text/css; charset=utf-8",
    "holder.js": "text/javascript; charset=utf-8",
    "holder-core.js": "text/javascript; charset=utf-8",
    "blindrsa.js": "text/javascript; charset=utf-8",
}
WEBAPP_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
}

_ERROR_STATUS = {
    "invalid_init_data": 401,
    "bot_account": 403,
    "premium_required": 403,
    "already_issued": 409,
    "invalid_request": 400,
}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    try:
        # validate=True rejects characters outside the alphabet instead of skipping them.
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise HTTPException(status_code=400, detail={"code": "invalid_encoding"}) from exc


def key_id(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()[:16]


@dataclass(frozen=True)
class Settings:
    bot_id: int
    issuer_key_file: str
    pseudonym_key: bytes
    db_path: str
    registry_db_path: str = "tgtrust-registry.db"
    deals_db_path: str = "tgtrust-deals.db"
    disputes_db_path: str = "tgtrust-disputes.db"
    arbiter_public_key: str = ""
    telegram_env: str = "production"
    require_premium: bool = False
    epoch: str = "v1"
    rate_limit_per_minute: int = 20
    trust_forwarded_for: bool = False
    stake_contract: str = ""
    ton_network: str = "testnet"
    toncenter_api_key: str = ""
    stake_cache_seconds: int = 30

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        missing = [
            name
            for name in ("TGTRUST_BOT_ID", "TGTRUST_ISSUER_KEY_FILE", "TGTRUST_PSEUDONYM_KEY")
            if not env.get(name)
        ]
        if missing:
            raise RuntimeError(f"missing settings: {', '.join(missing)}")
        problems: list[str] = []

        def check(name: str, parse, default: str = ""):
            raw = env.get(name)
            text = default if raw is None else raw.strip()
            try:
                return parse(text)
            except _BadSetting as exc:
                problems.append(f"{name}: {exc}")
                return None

        bot_id = check("TGTRUST_BOT_ID", _parse_bot_id)
        pseudonym_key = check("TGTRUST_PSEUDONYM_KEY", _parse_pseudonym_key)
        require_premium = check("TGTRUST_REQUIRE_PREMIUM", _parse_flag)
        trust_forwarded_for = check("TGTRUST_TRUST_FORWARDED_FOR", _parse_flag)
        rate_limit = check("TGTRUST_RATE_LIMIT", lambda t: _parse_int(t, 1), "20")
        stake_cache = check("TGTRUST_STAKE_CACHE_SECONDS", lambda t: _parse_int(t, 0), "30")
        telegram_env = check("TGTRUST_TELEGRAM_ENV", lambda t: _parse_choice(t, TELEGRAM_PUBLIC_KEYS), "production")
        ton_network = check("TGTRUST_TON_NETWORK", lambda t: _parse_choice(t, ENDPOINTS), "testnet")
        arbiter = check("TGTRUST_ARBITER_PUBLIC_KEY", _parse_arbiter_key)
        if problems:
            raise RuntimeError("invalid settings: " + "; ".join(problems))
        return cls(
            bot_id=bot_id,
            issuer_key_file=env["TGTRUST_ISSUER_KEY_FILE"],
            pseudonym_key=pseudonym_key,
            db_path=env.get("TGTRUST_DB_PATH", "tgtrust.db"),
            registry_db_path=env.get("TGTRUST_REGISTRY_DB_PATH", "tgtrust-registry.db"),
            deals_db_path=env.get("TGTRUST_DEALS_DB_PATH", "tgtrust-deals.db"),
            disputes_db_path=env.get("TGTRUST_DISPUTES_DB_PATH", "tgtrust-disputes.db"),
            arbiter_public_key=arbiter,
            telegram_env=telegram_env,
            require_premium=require_premium,
            epoch=env.get("TGTRUST_EPOCH", "v1"),
            rate_limit_per_minute=rate_limit,
            trust_forwarded_for=trust_forwarded_for,
            stake_contract=env.get("TGTRUST_STAKE_CONTRACT", ""),
            ton_network=ton_network,
            toncenter_api_key=env.get("TGTRUST_TONCENTER_API_KEY", ""),
            stake_cache_seconds=stake_cache,
        )


import re  # noqa: E402  (kept next to the settings helpers below)

from .stake import ENDPOINTS  # noqa: E402
from .telegram_sig import TELEGRAM_PUBLIC_KEYS  # noqa: E402


class _BadSetting(Exception):
    """A wrong setting value; the message is the reason and never contains secret values."""


_HEX = frozenset("0123456789abcdefABCDEF")


def _parse_bot_id(text: str) -> int:
    if ":" in text:
        raise _BadSetting("this looks like a bot token; only the number before the colon belongs here")
    if not (text.isascii() and text.isdigit()) or int(text) <= 0:
        raise _BadSetting("must be digits only and greater than 0")
    return int(text)


def _parse_pseudonym_key(text: str) -> bytes:
    if not text or len(text) % 2 or not set(text) <= _HEX:
        raise _BadSetting("must be hexadecimal text of at least 64 characters")
    if len(text) < 64:
        raise _BadSetting("too short: at least 32 bytes (64 hex characters) are required")
    return bytes.fromhex(text)


def _parse_flag(text: str) -> bool:
    if text in ("", "0"):
        return False
    if text == "1":
        return True
    raise _BadSetting(f"got {text!r}, use 1 or 0")


def _parse_int(text: str, minimum: int) -> int:
    if not re.fullmatch(r"-?[0-9]+", text):
        raise _BadSetting(f"got {text!r}, must be a whole number")
    value = int(text)
    if value < minimum:
        raise _BadSetting(f"got {text!r}, must be {minimum} or more")
    return value


def _parse_choice(text: str, allowed) -> str:
    if text not in allowed:
        raise _BadSetting(f"got {text!r}, must be one of: {', '.join(allowed)}")
    return text


def _parse_arbiter_key(text: str) -> str:
    if text and (len(text) != 64 or not set(text) <= _HEX):
        raise _BadSetting("must be empty or exactly 64 hex characters")
    return text


class RateLimiter:
    """Sliding one-minute window per client key."""

    def __init__(self, limit_per_minute: int) -> None:
        self._limit = limit_per_minute
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = float("-inf")

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            if now - self._last_sweep >= 60:
                # Drop clients idle for a full window so the table cannot grow without bound.
                self._hits = defaultdict(deque, {k: v for k, v in self._hits.items() if v and now - v[-1] < 60})
                self._last_sweep = now
            hits = self._hits[key]
            while hits and now - hits[0] >= 60:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True

    def tracked(self) -> int:
        with self._lock:
            return len(self._hits)


class IssueRequest(BaseModel):
    init_data: str = Field(min_length=1, max_length=8192)
    blinded_message: str = Field(min_length=1, max_length=2048)


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1, max_length=128)
    signature: str = Field(min_length=1, max_length=2048)


class RegisterRequest(VerifyRequest):
    agent_public_key: str = Field(min_length=1, max_length=128)
    salt: str = Field(min_length=1, max_length=64)
    challenge: str = Field(min_length=1, max_length=128)
    agent_signature: str = Field(min_length=1, max_length=128)

class DealRequest(BaseModel):
    deal_id: str = Field(max_length=64)
    key_x: str = Field(max_length=64)
    key_y: str = Field(max_length=64)
    amount_nanogram: int = Field(ge=0, le=2**63 - 1)
    created_at: int = Field(ge=0, le=2**63 - 1)
    memo_hash: str | None = Field(default=None, max_length=64)
    signature_x: str = Field(max_length=128)
    signature_y: str = Field(max_length=128)


_DEAL_STATUS = {"bad_signature": 403, "unregistered_party": 403, "duplicate": 409, "stale": 400,
                "same_party": 400, "invalid_record": 400}

class DisputeRequest(BaseModel):
    deal_id: str = Field(max_length=64)
    claimant_key: str = Field(max_length=64)
    accused_key: str = Field(max_length=64)
    reason_hash: str | None = Field(default=None, max_length=64)
    payout_address: str = Field(min_length=1, max_length=80)
    filed_at: int = Field(ge=0, le=2**63 - 1)
    claimant_signature: str = Field(max_length=128)


class VerdictRequest(BaseModel):
    outcome: int = Field(ge=1, le=2)
    slash_amount_nanogram: int = Field(ge=0, le=2**63 - 1)
    decided_at: int = Field(ge=0, le=2**63 - 1)
    arbiter_signature: str = Field(max_length=128)


_DISPUTE_STATUS = {"bad_signature": 403, "not_a_party": 403, "duplicate": 409, "already_decided": 409,
                   "unknown_case": 404, "no_arbiter": 503}


def _open_db(setting: str, path: str, build):
    """Run ``build()`` (which opens the database at ``path``); a file that cannot be opened stops the start
    with one line naming the setting and the path."""
    try:
        return build()
    except sqlite3.Error as exc:
        raise RuntimeError(f"cannot open database {setting}={path}: {exc}") from exc


def _read_issuer_key(setting: str, path: str):
    """Load the issuer's RSA private key from ``path``; any problem stops the start with one line naming the
    setting and the path. The line never carries file content or the text of the underlying exception."""
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import rsa

    def fail(reason: str):
        return RuntimeError(f"cannot load issuer key {setting}={path}: {reason}")

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        raise fail("file not found") from None
    except IsADirectoryError:
        raise fail("is a directory") from None
    except OSError as exc:
        # Windows reports a directory as PermissionError, not IsADirectoryError.
        if os.path.isdir(path):
            raise fail("is a directory") from None
        raise fail(f"cannot read file {type(exc).__name__}") from None
    if not data.strip():
        raise fail("file is empty")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        raise fail("key is password-protected; the service needs an unencrypted key") from None
    except (ValueError, UnsupportedAlgorithm):
        raise fail("not a PEM private key") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise fail(f"not an RSA key (found {type(key).__name__})")
    if key.key_size < 2048:
        raise fail(f"RSA key is {key.key_size} bits; at least 2048 are required")
    return key


def load_issuer(settings: Settings) -> Issuer:
    private_key = _read_issuer_key("TGTRUST_ISSUER_KEY_FILE", settings.issuer_key_file)
    return Issuer(
        private_key,
        settings.bot_id,
        settings.pseudonym_key,
        _open_db("TGTRUST_DB_PATH", settings.db_path, lambda: SqliteIssuedStore(settings.db_path)),
        policy=IssuerPolicy(require_premium=settings.require_premium, epoch=settings.epoch),
        environment=settings.telegram_env,
    )


def create_app(
    settings: Settings | None = None,
    *,
    issuer: Issuer | None = None,
    registry: Registry | None = None,
    stake_reader: StakeReader | None = None,
    deals: DealLedger | None = None,
    disputes: DisputeBook | None = None,
    rate_limit_per_minute: int | None = None,
    trust_forwarded_for: bool | None = None,
) -> FastAPI:
    if issuer is None:
        settings = settings or Settings.from_env()
        issuer = load_issuer(settings)
    limit = rate_limit_per_minute or (settings.rate_limit_per_minute if settings else 20)
    forwarded = trust_forwarded_for if trust_forwarded_for is not None else bool(
        settings and settings.trust_forwarded_for
    )

    public_key = issuer.public_key
    kid = key_id(public_key)
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    limiter = RateLimiter(limit)
    if registry is None:
        if settings:
            registry = _open_db("TGTRUST_REGISTRY_DB_PATH", settings.registry_db_path,
                                lambda: Registry(public_key, kid, settings.registry_db_path))
        else:
            registry = Registry(public_key, kid, ":memory:")

    if stake_reader is None and settings and settings.stake_contract:
        stake_reader = StakeReader(
            settings.stake_contract,
            settings.ton_network,
            cache_seconds=settings.stake_cache_seconds,
            api_key=settings.toncenter_api_key or None,
        )
    stake_source = StakeSource(stake_reader.network, stake_reader.contract) if stake_reader else None

    def has_active_stake(agent_hex: str) -> bool:
        if stake_reader is None:
            return False
        info = stake_reader.get_stake(agent_hex)
        return info.found and info.amount > 0 and not info.withdrawing

    if deals is None:
        if settings:
            deals = _open_db("TGTRUST_DEALS_DB_PATH", settings.deals_db_path,
                             lambda: DealLedger(registry, settings.deals_db_path, stake_check=has_active_stake))
        else:
            deals = DealLedger(registry, ":memory:", stake_check=has_active_stake)
    if disputes is None:
        arbiter_key = bytes.fromhex(settings.arbiter_public_key) if settings and settings.arbiter_public_key else None
        if settings:
            disputes = _open_db("TGTRUST_DISPUTES_DB_PATH", settings.disputes_db_path,
                                lambda: DisputeBook(deals, arbiter_key, settings.disputes_db_path))
        else:
            disputes = DisputeBook(deals, arbiter_key, ":memory:")

    app = FastAPI(title="tgtrust issuer", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default body echoes the rejected input back; a lone surrogate or NaN in it made the
        # JSON response itself fail (HTTP 500). Report only where and what kind of error, never the input.
        detail = [{"loc": [str(part) for part in err.get("loc", ())], "type": str(err.get("type", "invalid"))}
                  for err in exc.errors()]
        return JSONResponse({"detail": detail}, status_code=422)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": {"code": "body_too_large"}}, status_code=413)
        if request.method == "POST" and not (length and length.isdigit()):
            # No usable Content-Length (chunked transfer or a malformed header): count the bytes as they
            # arrive so the cap still holds, then replay the body to the endpoint.
            body = bytearray()
            async for chunk in request.stream():
                body += chunk
                if len(body) > MAX_BODY_BYTES:
                    return JSONResponse({"detail": {"code": "body_too_large"}}, status_code=413)
            data = bytes(body)

            async def replay() -> dict:
                return {"type": "http.request", "body": data, "more_body": False}

            request = Request(request.scope, replay)
        if request.method == "POST":
            client = request.client.host if request.client else "unknown"
            if forwarded and request.headers.get("x-forwarded-for"):
                # The reverse proxy appends the address it saw, so only the last entry is trustworthy;
                # earlier entries are whatever the client chose to send.
                client = request.headers["x-forwarded-for"].split(",")[-1].strip() or client
            if not limiter.allow(client):
                return JSONResponse({"detail": {"code": "rate_limited"}}, status_code=429)
        return await call_next(request)

    @app.get("/v1/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/app/")
    @app.get("/app/{name}")
    def webapp(name: str = "holder.html") -> Response:
        content_type = WEBAPP_FILES.get(name)
        if content_type is None:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        return Response((WEBAPP_DIR / name).read_bytes(), media_type=content_type, headers=WEBAPP_HEADERS)

    @app.get("/v1/issuer")
    def issuer_info() -> dict:
        return {
            "key_id": kid,
            "scheme": SCHEME,
            "public_key_pem": public_pem,
            "credential_prefix": CREDENTIAL_PREFIX.decode(),
            "require_premium": issuer._policy.require_premium,
            "epoch": issuer._policy.epoch,
        }

    @app.post("/v1/issue")
    def issue(body: IssueRequest) -> dict:
        blinded = b64url_decode(body.blinded_message)
        try:
            blind_signature = issuer.issue(body.init_data, blinded)
        except IssuanceError as exc:
            raise HTTPException(
                status_code=_ERROR_STATUS.get(exc.code, 400), detail={"code": exc.code}
            ) from exc
        return {"blind_signature": b64url_encode(blind_signature), "key_id": kid}

    @app.post("/v1/verify")
    def verify(body: VerifyRequest) -> dict:
        credential = Credential(b64url_decode(body.token), b64url_decode(body.signature))
        return {"valid": verify_credential(public_key, credential), "key_id": kid}

    @app.post("/v1/challenge")
    def challenge() -> dict:
        return {"challenge": b64url_encode(registry.new_challenge())}

    @app.post("/v1/register")
    def register(body: RegisterRequest) -> dict:
        credential = Credential(b64url_decode(body.token), b64url_decode(body.signature))
        try:
            record = registry.register(
                credential,
                b64url_decode(body.agent_public_key),
                b64url_decode(body.salt),
                b64url_decode(body.challenge),
                b64url_decode(body.agent_signature),
            )
        except RegistrationError as exc:
            raise HTTPException(
                status_code=_REGISTRATION_STATUS.get(exc.code, 400), detail={"code": exc.code}
            ) from exc
        return record.badge()

    @app.get("/v1/agents/{agent_public_key_hex}")
    def agent_badge(agent_public_key_hex: str) -> dict:
        if len(agent_public_key_hex) != 64 or any(c not in "0123456789abcdefABCDEF" for c in agent_public_key_hex):
            raise HTTPException(status_code=400, detail={"code": "invalid_agent_key"})
        record = registry.lookup(agent_public_key_hex)
        if record is None:
            raise HTTPException(status_code=404, detail={"code": "unknown_agent"})
        return record.badge()

    @app.get("/v1/agents/{agent_public_key_hex}/badge")
    def trust_badge(agent_public_key_hex: str) -> dict:
        """One call: uniqueness (registry) + stake (TON contract) + history."""
        if len(agent_public_key_hex) != 64 or any(c not in "0123456789abcdefABCDEF" for c in agent_public_key_hex):
            raise HTTPException(status_code=400, detail={"code": "invalid_agent_key"})
        record = registry.lookup(agent_public_key_hex)
        stake = None
        stake_error = None
        if stake_reader is not None:
            try:
                stake = stake_reader.get_stake(agent_public_key_hex)
            except StakeLookupError as exc:
                stake_error = str(exc)
        return build_badge(
            agent_public_key_hex,
            record,
            stake,
            stake_source=stake_source,
            stake_error=stake_error,
            deals=deals.stats(agent_public_key_hex),
            disputes=disputes.stats(agent_public_key_hex),
            now=int(time.time()),
        )

    @app.post("/v1/deals")
    def record_deal(body: DealRequest) -> dict:
        try:
            row = deals.record(
                b64url_decode(body.deal_id),
                b64url_decode(body.key_x),
                b64url_decode(body.key_y),
                body.amount_nanogram,
                body.created_at,
                b64url_decode(body.memo_hash) if body.memo_hash else bytes(32),
                b64url_decode(body.signature_x),
                b64url_decode(body.signature_y),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"code": "invalid_encoding"}) from exc
        except DealError as exc:
            raise HTTPException(status_code=_DEAL_STATUS.get(exc.code, 400), detail={"code": exc.code}) from exc
        return row.to_dict()

    @app.get("/v1/agents/{agent_public_key_hex}/deals")
    def agent_deals(agent_public_key_hex: str, limit: int = 20) -> dict:
        if len(agent_public_key_hex) != 64 or any(c not in "0123456789abcdefABCDEF" for c in agent_public_key_hex):
            raise HTTPException(status_code=400, detail={"code": "invalid_agent_key"})
        limit = max(1, min(limit, 100))
        return {
            "agent": agent_public_key_hex.lower(),
            "stats": deals.stats(agent_public_key_hex).to_dict(),
            "deals": [d.to_dict() for d in deals.deals_of(agent_public_key_hex, limit)],
        }

    @app.post("/v1/disputes")
    def file_dispute(body: DisputeRequest) -> dict:
        try:
            case = disputes.file(
                b64url_decode(body.deal_id),
                b64url_decode(body.claimant_key),
                b64url_decode(body.accused_key),
                b64url_decode(body.reason_hash) if body.reason_hash else bytes(32),
                body.payout_address,
                body.filed_at,
                b64url_decode(body.claimant_signature),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"code": "invalid_encoding"}) from exc
        except DisputeError as exc:
            raise HTTPException(status_code=_DISPUTE_STATUS.get(exc.code, 400), detail={"code": exc.code}) from exc
        return case.to_dict()

    @app.post("/v1/disputes/{case_id}/verdict")
    def decide_dispute(body: VerdictRequest, case_id: int = Path(ge=0, le=MAX_CASE_ID)) -> dict:
        try:
            case = disputes.decide(case_id, body.outcome, body.slash_amount_nanogram, body.decided_at,
                                   b64url_decode(body.arbiter_signature))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"code": "invalid_encoding"}) from exc
        except DisputeError as exc:
            raise HTTPException(status_code=_DISPUTE_STATUS.get(exc.code, 400), detail={"code": exc.code}) from exc
        return case.to_dict()

    @app.get("/v1/disputes/{case_id}")
    def get_dispute(case_id: int = Path(ge=0, le=MAX_CASE_ID)) -> dict:
        case = disputes.get(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail={"code": "unknown_case"})
        return case.to_dict()

    @app.get("/v1/agents/{agent_public_key_hex}/disputes")
    def agent_disputes(agent_public_key_hex: str, limit: int = 20) -> dict:
        if len(agent_public_key_hex) != 64 or any(c not in "0123456789abcdefABCDEF" for c in agent_public_key_hex):
            raise HTTPException(status_code=400, detail={"code": "invalid_agent_key"})
        limit = max(1, min(limit, 100))
        return {
            "agent": agent_public_key_hex.lower(),
            "stats": disputes.stats(agent_public_key_hex).to_dict(),
            "cases": [c.to_dict() for c in disputes.cases_against(agent_public_key_hex, limit)],
        }

    return app
