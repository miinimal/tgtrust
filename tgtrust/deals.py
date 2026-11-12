"""Confirmed-deals ledger (block 7): the third fact a badge can show.

A deal record names two registered agents and is valid only when both agent keys
signed the same canonical bytes. The ledger stores nothing about owners. It records,
at submission time, whether each party held an active stake, so a bot can count
"deals with staked counterparties" — the number that is expensive to farm, because
every such counterparty had Gram at risk and a unique Telegram user behind it.

Canonical bytes signed by both parties:
    DEAL_PREFIX || deal_id(16) || key_a(32) || key_b(32) || amount(8, big-endian nanograms)
    || created_at(8, big-endian unix seconds) || memo_hash(32)
with key_a < key_b (bytes order), so the record has one canonical form.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .registry import Registry

DEAL_PREFIX = b"tgtrust/v1/deal:"
DEAL_ID_BYTES = 16
MAX_SKEW_SECONDS = 3600
MAX_AMOUNT = 2**63 - 1


class DealError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DealRecord:
    deal_id: str  # hex
    key_a: str  # hex, the smaller key
    key_b: str  # hex
    amount: int  # nanograms, informational
    created_at: int
    memo_hash: str  # hex, 32 bytes (zeros when unused)
    a_staked: bool
    b_staked: bool
    recorded_at: int

    def to_dict(self) -> dict:
        return {
            "deal_id": self.deal_id,
            "parties": [self.key_a, self.key_b],
            "amount_nanogram": self.amount,
            "created_at": self.created_at,
            "memo_hash": self.memo_hash,
            "staked": {self.key_a: self.a_staked, self.key_b: self.b_staked},
            "recorded_at": self.recorded_at,
        }


def canonical_bytes(deal_id: bytes, key_a: bytes, key_b: bytes, amount: int, created_at: int, memo_hash: bytes) -> bytes:
    if len(deal_id) != DEAL_ID_BYTES or len(key_a) != 32 or len(key_b) != 32 or len(memo_hash) != 32:
        raise ValueError("bad field lengths")
    if not (0 <= amount <= MAX_AMOUNT) or not (0 <= created_at <= MAX_AMOUNT):
        raise ValueError("amount and created_at must be non-negative 63-bit integers")
    if key_a >= key_b:
        raise ValueError("keys must be ordered: key_a < key_b")
    return DEAL_PREFIX + deal_id + key_a + key_b + amount.to_bytes(8, "big") + created_at.to_bytes(8, "big") + memo_hash


def order_keys(key_x: bytes, key_y: bytes) -> tuple[bytes, bytes]:
    return (key_x, key_y) if key_x < key_y else (key_y, key_x)


@dataclass(frozen=True)
class DealStats:
    count: int
    with_staked_counterparty: int
    distinct_counterparties: int
    first_at: int | None
    last_at: int | None

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "with_staked_counterparty": self.with_staked_counterparty,
            "distinct_counterparties": self.distinct_counterparties,
            "first_at": self.first_at,
            "last_at": self.last_at,
        }


StakeCheck = Callable[[str], bool]  # agent key hex -> has an active stake now


class DealLedger:
    def __init__(self, registry: Registry, db_path: str = ":memory:", *, stake_check: StakeCheck | None = None,
                 clock: Callable[[], float] = time.time):
        self._registry = registry
        self._stake_check = stake_check
        self._clock = clock
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS deals (
                deal_id TEXT PRIMARY KEY,
                key_a TEXT NOT NULL,
                key_b TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                memo_hash TEXT NOT NULL,
                a_staked INTEGER NOT NULL,
                b_staked INTEGER NOT NULL,
                recorded_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS deals_a ON deals(key_a);
            CREATE INDEX IF NOT EXISTS deals_b ON deals(key_b);
            """
        )

    def record(
        self,
        deal_id: bytes,
        key_x: bytes,
        key_y: bytes,
        amount: int,
        created_at: int,
        memo_hash: bytes,
        sig_x: bytes,
        sig_y: bytes,
    ) -> DealRecord:
        """Stores a deal after checking both signatures and both registrations."""
        if key_x == key_y:
            raise DealError("same_party", "a deal needs two different agents")
        now = int(self._clock())
        if abs(now - created_at) > MAX_SKEW_SECONDS:
            raise DealError("stale", "created_at is too far from now")
        key_a, key_b = order_keys(key_x, key_y)
        sig_a, sig_b = (sig_x, sig_y) if key_a == key_x else (sig_y, sig_x)
        try:
            message = canonical_bytes(deal_id, key_a, key_b, amount, created_at, memo_hash)
        except ValueError as exc:
            raise DealError("invalid_record", str(exc)) from exc
        for key, sig, who in ((key_a, sig_a, "a"), (key_b, sig_b, "b")):
            try:
                Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
            except (InvalidSignature, ValueError) as exc:
                raise DealError("bad_signature", f"signature of party {who} is invalid") from exc
        hex_a, hex_b = key_a.hex(), key_b.hex()
        for hexkey in (hex_a, hex_b):
            rec = self._registry.lookup(hexkey)
            if rec is None or rec.revoked:
                raise DealError("unregistered_party", f"agent {hexkey[:16]} is not a registered unique agent")
        a_staked = bool(self._stake_check and self._safe_stake(hex_a))
        b_staked = bool(self._stake_check and self._safe_stake(hex_b))
        row = DealRecord(deal_id.hex(), hex_a, hex_b, amount, created_at, memo_hash.hex(), a_staked, b_staked, now)
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO deals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (row.deal_id, row.key_a, row.key_b, row.amount, row.created_at, row.memo_hash,
                     int(row.a_staked), int(row.b_staked), row.recorded_at),
                )
            except sqlite3.IntegrityError as exc:
                raise DealError("duplicate", "deal_id already recorded") from exc
        return row

    def _safe_stake(self, hexkey: str) -> bool:
        try:
            return bool(self._stake_check(hexkey))  # type: ignore[misc]
        except Exception:  # noqa: BLE001 - a stake lookup failure must not block a valid deal
            return False

    def deals_of(self, agent_hex: str, limit: int = 50) -> list[DealRecord]:
        agent_hex = agent_hex.lower()
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM deals WHERE key_a = ? OR key_b = ? ORDER BY created_at DESC LIMIT ?",
                (agent_hex, agent_hex, limit),
            ).fetchall()
        return [DealRecord(r[0], r[1], r[2], r[3], r[4], r[5], bool(r[6]), bool(r[7]), r[8]) for r in rows]

    def stats(self, agent_hex: str) -> DealStats:
        agent_hex = agent_hex.lower()
        with self._lock:
            rows = self._conn.execute(
                "SELECT key_a, key_b, a_staked, b_staked, created_at FROM deals WHERE key_a = ? OR key_b = ?",
                (agent_hex, agent_hex),
            ).fetchall()
        if not rows:
            return DealStats(0, 0, 0, None, None)
        with_staked = 0
        counterparties = set()
        times = []
        for key_a, key_b, a_staked, b_staked, created_at in rows:
            other, other_staked = (key_b, b_staked) if key_a == agent_hex else (key_a, a_staked)
            counterparties.add(other)
            with_staked += int(bool(other_staked))
            times.append(created_at)
        return DealStats(len(rows), with_staked, len(counterparties), min(times), max(times))
