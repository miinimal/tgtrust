"""Anonymous credential issuance bound to unique Telegram accounts.

Flow (path A of the concept):
  1. The holder opens the issuer Mini App; Telegram signs the init data.
  2. The holder creates a random token and blinds it (``Holder.prepare``).
  3. The issuer verifies Telegram's signature, checks the account has not
     received a credential yet, and blind-signs (``Issuer.issue``).
  4. The holder unblinds (``Holder.finalize``) and obtains a credential that
     anyone can verify with the issuer public key, but nobody, the issuer
     included, can link back to the Telegram account.

The issuer stores only a keyed pseudonym of each account (HMAC), never raw
user ids, so a leaked store does not reveal who holds credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import rsa

from . import blind_rsa
from .telegram_sig import InitDataError, verify_init_data

CREDENTIAL_PREFIX = b"tgtrust/v1/credential:"
TOKEN_BYTES = 32


class IssuanceError(Exception):
    """Raised when a credential cannot be issued; ``code`` is machine-readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class IssuedStore(Protocol):
    """Records which account pseudonyms already received a credential."""

    def contains(self, tag: bytes) -> bool: ...

    def request_digest(self, tag: bytes) -> bytes | None:
        """Digest of the blinded request served for ``tag``; None if nothing was issued.

        An empty value means a credential was issued before digests were recorded."""
        ...

    def add_if_absent(self, tag: bytes, request_digest: bytes = b"") -> bool:
        """Atomically record ``tag``. Returns False if it was already present."""
        ...


class MemoryIssuedStore:
    """In-process store for tests and development."""

    def __init__(self) -> None:
        self._tags: dict[bytes, bytes] = {}
        self._lock = threading.Lock()

    def contains(self, tag: bytes) -> bool:
        with self._lock:
            return tag in self._tags

    def request_digest(self, tag: bytes) -> bytes | None:
        with self._lock:
            return self._tags.get(tag)

    def add_if_absent(self, tag: bytes, request_digest: bytes = b"") -> bool:
        with self._lock:
            if tag in self._tags:
                return False
            self._tags[tag] = request_digest
            return True


class SqliteIssuedStore:
    """Persistent store; uniqueness is enforced by the database primary key."""

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS issued (tag BLOB PRIMARY KEY, created_at INTEGER "
            "NOT NULL DEFAULT (strftime('%s','now')))"
        )
        # Databases created before retries were supported have no digest column; add it in place.
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(issued)")}
        if "request_digest" not in columns:
            self._conn.execute("ALTER TABLE issued ADD COLUMN request_digest BLOB")

    def contains(self, tag: bytes) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM issued WHERE tag = ?", (tag,)).fetchone()
            return row is not None

    def request_digest(self, tag: bytes) -> bytes | None:
        with self._lock:
            row = self._conn.execute("SELECT request_digest FROM issued WHERE tag = ?", (tag,)).fetchone()
        if row is None:
            return None
        return bytes(row[0]) if row[0] is not None else b""

    def add_if_absent(self, tag: bytes, request_digest: bytes = b"") -> bool:
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO issued (tag, request_digest) VALUES (?, ?)", (tag, request_digest)
            )
            return cur.rowcount == 1

    def close(self) -> None:
        self._conn.close()


@dataclass(frozen=True)
class IssuerPolicy:
    require_premium: bool = False
    max_init_data_age_seconds: int = 900
    # Scope of uniqueness; rotating it (e.g. per year) allows re-issuance.
    epoch: str = "v1"


class Issuer:
    def __init__(
        self,
        private_key: rsa.RSAPrivateKey,
        bot_id: int,
        pseudonym_key: bytes,
        store: IssuedStore,
        *,
        policy: IssuerPolicy | None = None,
        environment: str = "production",
        telegram_public_key_hex: str | None = None,
    ) -> None:
        if len(pseudonym_key) < 32:
            raise ValueError("pseudonym_key must be at least 32 bytes")
        self._private_key = private_key
        self._bot_id = bot_id
        self._pseudonym_key = pseudonym_key
        self._store = store
        self._policy = policy or IssuerPolicy()
        self._environment = environment
        self._telegram_public_key_hex = telegram_public_key_hex

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._private_key.public_key()

    def _account_tag(self, user_id: int) -> bytes:
        msg = f"{self._policy.epoch}:{self._bot_id}:{user_id}".encode()
        return hmac.new(self._pseudonym_key, msg, hashlib.sha256).digest()

    def issue(self, init_data: str, blinded_message: bytes, *, now: int | None = None) -> bytes:
        """Verify the Telegram account and blind-sign one credential for it."""
        try:
            verified = verify_init_data(
                init_data,
                self._bot_id,
                environment=self._environment,
                public_key_hex=self._telegram_public_key_hex,
                max_age_seconds=self._policy.max_init_data_age_seconds,
                now=now,
            )
        except InitDataError as exc:
            raise IssuanceError("invalid_init_data", str(exc)) from exc

        if verified.is_bot:
            raise IssuanceError("bot_account", "bots cannot receive credentials")
        if self._policy.require_premium and not verified.is_premium:
            raise IssuanceError("premium_required", "Telegram Premium is required")

        tag = self._account_tag(verified.user_id)
        digest = hashlib.sha256(blinded_message).digest()
        if self._store.contains(tag) and not self._is_retry(tag, digest):
            raise IssuanceError("already_issued", "this account already has a credential")

        try:
            signature = blind_rsa.blind_sign(self._private_key, blinded_message)
        except blind_rsa.BlindSignatureError as exc:
            raise IssuanceError("invalid_request", str(exc)) from exc

        # Record only after signing succeeded; a concurrent duplicate loses the race
        # unless it is the very same request, which gets the very same signature.
        if not self._store.add_if_absent(tag, digest) and not self._is_retry(tag, digest):
            raise IssuanceError("already_issued", "this account already has a credential")
        return signature

    def _is_retry(self, tag: bytes, digest: bytes) -> bool:
        """True when this account already received a signature for exactly this blinded request.

        Signing is deterministic, so answering the same request again releases nothing new: the
        account still ends up with one credential. It lets a holder whose connection dropped after
        the issuer recorded the request, but before the answer arrived, ask again instead of
        losing the only credential of the epoch."""
        stored = self._store.request_digest(tag)
        return bool(stored) and hmac.compare_digest(stored, digest)


@dataclass(frozen=True)
class Credential:
    token: bytes
    signature: bytes

    @property
    def message(self) -> bytes:
        return CREDENTIAL_PREFIX + self.token


@dataclass(frozen=True)
class PendingRequest:
    token: bytes
    blinded_message: bytes
    state: blind_rsa.BlindingState


class Holder:
    """Agent owner side of issuance."""

    def __init__(self, issuer_public_key: rsa.RSAPublicKey) -> None:
        self._issuer_public_key = issuer_public_key

    def prepare(self, token: bytes | None = None) -> PendingRequest:
        """Blind a token for issuance; pass ``registry.agent_token(...)`` to bind an agent."""
        token = secrets.token_bytes(TOKEN_BYTES) if token is None else token
        if len(token) != TOKEN_BYTES:
            raise ValueError("token must be 32 bytes")
        blinded, state = blind_rsa.blind(self._issuer_public_key, CREDENTIAL_PREFIX + token)
        return PendingRequest(token=token, blinded_message=blinded, state=state)

    def finalize(self, request: PendingRequest, blind_signature: bytes) -> Credential:
        signature = blind_rsa.finalize(
            self._issuer_public_key, CREDENTIAL_PREFIX + request.token, blind_signature, request.state
        )
        return Credential(token=request.token, signature=signature)


def verify_credential(issuer_public_key: rsa.RSAPublicKey, credential: Credential) -> bool:
    """Check that a credential was issued by the given issuer."""
    if len(credential.token) != TOKEN_BYTES:
        return False
    return blind_rsa.verify(issuer_public_key, credential.message, credential.signature)
