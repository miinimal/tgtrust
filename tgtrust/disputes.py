"""Disputes (block 9): from a confirmed deal to an arbiter verdict and an on-chain slash.

Flow
1. A party of a recorded deal files a case, signed with its agent key. It names the
   accused party and a payout address (any TON address the claimant controls; it
   may be a fresh wallet, so the agent stays unlinked from its owner).
2. The arbiter decides off-chain and signs the verdict with the arbiter Ed25519 key.
   `upheld` verdicts carry a slash amount; the service stores the verdict and exposes
   the exact `Slash` message fields (agent key, amount, victim address, case id).
3. The arbiter's TON wallet sends `Slash` to StakeRegistry; the contract burns the case
   id, so a verdict can be executed at most once. The service never holds that wallet.

Canonical bytes
    case:    DISPUTE_PREFIX || deal_id(16) || claimant_key(32) || accused_key(32) || reason_hash(32) || filed_at(8)
    verdict: VERDICT_PREFIX || case_id(8) || outcome(1) || slash_amount(8) || decided_at(8)
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .deals import DealLedger

DISPUTE_PREFIX = b"tgtrust/v1/dispute:"
VERDICT_PREFIX = b"tgtrust/v1/verdict:"
MAX_SKEW_SECONDS = 3600
MAX_U63 = 2**63 - 1

OUTCOME_UPHELD = 1
OUTCOME_DISMISSED = 2
OUTCOMES = {OUTCOME_UPHELD: "upheld", OUTCOME_DISMISSED: "dismissed"}

STATUS_OPEN = "open"


class DisputeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Case:
    case_id: int  # 64-bit, the contract's one-time case id
    deal_id: str
    claimant_key: str
    accused_key: str
    reason_hash: str
    payout_address: str
    filed_at: int
    status: str  # open | upheld | dismissed
    slash_amount: int
    decided_at: int | None

    def to_dict(self) -> dict:
        d = {
            "case_id": self.case_id,
            "deal_id": self.deal_id,
            "claimant": self.claimant_key,
            "accused": self.accused_key,
            "reason_hash": self.reason_hash,
            "payout_address": self.payout_address,
            "filed_at": self.filed_at,
            "status": self.status,
            "decided_at": self.decided_at,
        }
        if self.status == "upheld":
            # exactly what the arbiter wallet must send to StakeRegistry
            d["slash"] = {
                "agent_key": self.accused_key,
                "amount_nanogram": self.slash_amount,
                "victim": self.payout_address,
                "case_id": self.case_id,
            }
        return d


@dataclass(frozen=True)
class DisputeStats:
    filed_against: int
    upheld_against: int
    open_against: int
    filed_by: int

    def to_dict(self) -> dict:
        return {
            "filed_against": self.filed_against,
            "upheld_against": self.upheld_against,
            "open_against": self.open_against,
            "filed_by": self.filed_by,
        }


def case_bytes(deal_id: bytes, claimant: bytes, accused: bytes, reason_hash: bytes, filed_at: int) -> bytes:
    if len(deal_id) != 16 or len(claimant) != 32 or len(accused) != 32 or len(reason_hash) != 32:
        raise ValueError("bad field lengths")
    if not (0 <= filed_at <= MAX_U63):
        raise ValueError("bad filed_at")
    return DISPUTE_PREFIX + deal_id + claimant + accused + reason_hash + filed_at.to_bytes(8, "big")


def verdict_bytes(case_id: int, outcome: int, slash_amount: int, decided_at: int) -> bytes:
    if outcome not in OUTCOMES or not (0 <= slash_amount <= MAX_U63) or not (0 <= decided_at <= MAX_U63):
        raise ValueError("bad verdict fields")
    if not (0 <= case_id < 2**64):
        raise ValueError("bad case id")
    return VERDICT_PREFIX + case_id.to_bytes(8, "big") + bytes([outcome]) + slash_amount.to_bytes(8, "big") + decided_at.to_bytes(8, "big")


def derive_case_id(deal_id: bytes, claimant: bytes) -> int:
    """Deterministic case id: one case per (deal, claimant), stable across retries.

    63 bits so it fits SQLite's signed INTEGER; the contract takes uint64, so it is always valid there."""
    return int.from_bytes(hashlib.sha256(b"tgtrust/v1/case:" + deal_id + claimant).digest()[:8], "big") & MAX_U63


def is_valid_ton_address(value: str) -> bool:
    """Accepts user-friendly (48 chars base64url) or raw `wc:hex64` forms; the chain validates the rest."""
    if len(value) == 48 and all(c.isalnum() or c in "-_" for c in value):
        return True
    if ":" in value:
        wc, _, h = value.partition(":")
        return wc.lstrip("-").isdigit() and len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h)
    return False


class DisputeBook:
    def __init__(self, deals: DealLedger, arbiter_public_key: bytes | None, db_path: str = ":memory:", *,
                 clock: Callable[[], float] = time.time):
        self._deals = deals
        self._arbiter = Ed25519PublicKey.from_public_bytes(arbiter_public_key) if arbiter_public_key else None
        self._clock = clock
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id INTEGER PRIMARY KEY,
                deal_id TEXT NOT NULL,
                claimant_key TEXT NOT NULL,
                accused_key TEXT NOT NULL,
                reason_hash TEXT NOT NULL,
                payout_address TEXT NOT NULL,
                filed_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                slash_amount INTEGER NOT NULL DEFAULT 0,
                decided_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS cases_accused ON cases(accused_key);
            CREATE INDEX IF NOT EXISTS cases_claimant ON cases(claimant_key);
            """
        )

    @property
    def has_arbiter(self) -> bool:
        return self._arbiter is not None

    def file(self, deal_id: bytes, claimant: bytes, accused: bytes, reason_hash: bytes, payout_address: str,
             filed_at: int, claimant_signature: bytes) -> Case:
        now = int(self._clock())
        if abs(now - filed_at) > MAX_SKEW_SECONDS:
            raise DisputeError("stale", "filed_at is too far from now")
        if not is_valid_ton_address(payout_address):
            raise DisputeError("bad_payout_address", "payout address is not a TON address")
        try:
            message = case_bytes(deal_id, claimant, accused, reason_hash, filed_at)
        except ValueError as exc:
            raise DisputeError("invalid_case", str(exc)) from exc
        try:
            Ed25519PublicKey.from_public_bytes(claimant).verify(claimant_signature, message)
        except (InvalidSignature, ValueError) as exc:
            raise DisputeError("bad_signature", "claimant signature is invalid") from exc
        deal = next((d for d in self._deals.deals_of(claimant.hex(), limit=10_000) if d.deal_id == deal_id.hex()), None)
        if deal is None:
            raise DisputeError("not_a_party", "claimant is not a party of this deal")
        parties = {deal.key_a, deal.key_b}
        if accused.hex() not in parties or accused == claimant:
            raise DisputeError("not_a_party", "accused must be the other party of the deal")
        case = Case(derive_case_id(deal_id, claimant), deal_id.hex(), claimant.hex(), accused.hex(), reason_hash.hex(),
                    payout_address, filed_at, STATUS_OPEN, 0, None)
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (case.case_id, case.deal_id, case.claimant_key, case.accused_key, case.reason_hash,
                     case.payout_address, case.filed_at, case.status, 0, None),
                )
            except sqlite3.IntegrityError as exc:
                raise DisputeError("duplicate", "this claimant already filed a case on this deal") from exc
        return case

    def decide(self, case_id: int, outcome: int, slash_amount: int, decided_at: int, arbiter_signature: bytes) -> Case:
        if self._arbiter is None:
            raise DisputeError("no_arbiter", "arbiter key is not configured")
        now = int(self._clock())
        if abs(now - decided_at) > MAX_SKEW_SECONDS:
            raise DisputeError("stale", "decided_at is too far from now")
        try:
            message = verdict_bytes(case_id, outcome, slash_amount, decided_at)
        except ValueError as exc:
            raise DisputeError("invalid_verdict", str(exc)) from exc
        if outcome == OUTCOME_UPHELD and slash_amount <= 0:
            raise DisputeError("invalid_verdict", "an upheld verdict needs a positive slash amount")
        if outcome == OUTCOME_DISMISSED and slash_amount != 0:
            raise DisputeError("invalid_verdict", "a dismissed verdict carries no slash")
        try:
            self._arbiter.verify(arbiter_signature, message)
        except InvalidSignature as exc:
            raise DisputeError("bad_signature", "arbiter signature is invalid") from exc
        with self._lock:
            row = self._conn.execute("SELECT status FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if row is None:
                raise DisputeError("unknown_case", "no such case")
            if row[0] != STATUS_OPEN:
                raise DisputeError("already_decided", "this case already has a verdict")
            self._conn.execute(
                "UPDATE cases SET status = ?, slash_amount = ?, decided_at = ? WHERE case_id = ?",
                (OUTCOMES[outcome], slash_amount, decided_at, case_id),
            )
        return self.get(case_id)  # type: ignore[return-value]

    def get(self, case_id: int) -> Case | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        return Case(*row) if row else None

    def cases_against(self, agent_hex: str, limit: int = 50) -> list[Case]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM cases WHERE accused_key = ? ORDER BY filed_at DESC LIMIT ?", (agent_hex.lower(), limit)
            ).fetchall()
        return [Case(*r) for r in rows]

    def stats(self, agent_hex: str) -> DisputeStats:
        agent_hex = agent_hex.lower()
        with self._lock:
            against = self._conn.execute("SELECT status FROM cases WHERE accused_key = ?", (agent_hex,)).fetchall()
            by = self._conn.execute("SELECT COUNT(*) FROM cases WHERE claimant_key = ?", (agent_hex,)).fetchone()[0]
        statuses = [r[0] for r in against]
        return DisputeStats(len(statuses), statuses.count("upheld"), statuses.count(STATUS_OPEN), by)
