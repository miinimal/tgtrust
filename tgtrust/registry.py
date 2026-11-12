"""Agent registry: binds an anonymous credential to exactly one agent key.

The credential token is not random: it commits to the agent's Ed25519 public
key, ``token = SHA-256(prefix || agent_public_key || salt)``. A stolen
credential is therefore useless for any other agent. Registration requires the
agent to sign a fresh single-use challenge, proving possession of its key.

What the registry publishes per agent: that a unique Telegram user stands
behind it, which issuer vouched for it, and when it registered. It never
learns or stores which Telegram account that is.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .issuer import Credential, verify_credential

TOKEN_PREFIX = b"tgtrust/v1/agent:"
BIND_PREFIX = b"tgtrust/v1/bind:"
SALT_BYTES = 16
CHALLENGE_TTL_SECONDS = 300


def agent_token(agent_public_key: bytes, salt: bytes) -> bytes:
    """Token the holder must get signed so the credential binds to this agent."""
    if len(agent_public_key) != 32 or len(salt) != SALT_BYTES:
        raise ValueError("agent key must be 32 bytes and salt 16 bytes")
    return hashlib.sha256(TOKEN_PREFIX + agent_public_key + salt).digest()


def bind_message(challenge: bytes, token: bytes) -> bytes:
    return BIND_PREFIX + challenge + token


class RegistrationError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AgentRecord:
    agent_public_key: str  # hex
    issuer_key_id: str
    registered_at: int
    revoked: bool

    def badge(self) -> dict:
        return {
            "agent": self.agent_public_key,
            "unique_owner": not self.revoked,
            "issuer_key_id": self.issuer_key_id,
            "registered_at": self.registered_at,
        }


class Registry:
    def __init__(self, issuer_public_key: rsa.RSAPublicKey, issuer_key_id: str, db_path: str = ":memory:"):
        self._issuer_public_key = issuer_public_key
        self._issuer_key_id = issuer_key_id
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                agent_key TEXT PRIMARY KEY,
                token_hash BLOB NOT NULL UNIQUE,
                issuer_key_id TEXT NOT NULL,
                registered_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS challenges (
                challenge BLOB PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );
            """
        )

    def new_challenge(self, *, now: int | None = None) -> bytes:
        now = int(time.time()) if now is None else now
        challenge = secrets.token_bytes(32)
        with self._lock:
            self._conn.execute("DELETE FROM challenges WHERE expires_at < ?", (now,))
            self._conn.execute(
                "INSERT INTO challenges (challenge, expires_at) VALUES (?, ?)",
                (challenge, now + CHALLENGE_TTL_SECONDS),
            )
        return challenge

    def _consume_challenge(self, challenge: bytes, now: int) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM challenges WHERE challenge = ? AND expires_at >= ?", (challenge, now)
            )
            return cur.rowcount == 1

    def register(
        self,
        credential: Credential,
        agent_public_key: bytes,
        salt: bytes,
        challenge: bytes,
        agent_signature: bytes,
        *,
        now: int | None = None,
    ) -> AgentRecord:
        now = int(time.time()) if now is None else now
        try:
            expected = agent_token(agent_public_key, salt)
        except ValueError as exc:
            raise RegistrationError("invalid_request", str(exc)) from exc
        if not secrets.compare_digest(expected, credential.token):
            raise RegistrationError("token_mismatch", "credential is bound to a different agent")
        if not verify_credential(self._issuer_public_key, credential):
            raise RegistrationError("invalid_credential", "credential signature is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(agent_public_key).verify(
                agent_signature, bind_message(challenge, credential.token)
            )
        except (InvalidSignature, ValueError) as exc:
            raise RegistrationError("invalid_agent_signature", "agent did not prove its key") from exc
        if not self._consume_challenge(challenge, now):
            raise RegistrationError("invalid_challenge", "challenge is unknown, used or expired")

        token_hash = hashlib.sha256(credential.token).digest()
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO agents (agent_key, token_hash, issuer_key_id, registered_at) "
                    "VALUES (?, ?, ?, ?)",
                    (agent_public_key.hex(), token_hash, self._issuer_key_id, now),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistrationError("already_registered", "credential or agent already registered") from exc
        return AgentRecord(agent_public_key.hex(), self._issuer_key_id, now, False)

    def lookup(self, agent_public_key_hex: str) -> AgentRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT agent_key, issuer_key_id, registered_at, revoked FROM agents WHERE agent_key = ?",
                (agent_public_key_hex.lower(),),
            ).fetchone()
        if row is None:
            return None
        return AgentRecord(row[0], row[1], row[2], bool(row[3]))

    def revoke(self, agent_public_key_hex: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agents SET revoked = 1 WHERE agent_key = ?", (agent_public_key_hex.lower(),)
            )
            return cur.rowcount == 1
