"""Trust gate for paid agent APIs: price and credit by tgtrust level, ready for x402.

An API that sells to agents (x402 or any other payment flow) has to decide, per request: does this unknown
agent pay first, or may it run up a small balance and pay later? The gate answers that from evidence:

1. the caller signs the request with its tgtrust agent key (``sign_request``), so the key is proven, not claimed;
2. the gate reads the key's badge from the issuer and, optionally, its Concordium Agent Registry link;
3. a ``Policy`` maps what was proven to a ``Tier`` (prepay or credit, with a limit).

The gate never moves money and never trusts a level the caller states about itself. Every decision carries the
evidence lines it was made from. ``x402_extra`` turns a decision into an ``extra.tgtrust`` object for the
x402 ``PaymentRequirements`` of a 402 reply; nothing else in the x402 reply is touched.

Request signature (``tgtrust-req/v1``), Ed25519 by the agent key over::

    b"tgtrust-req/v1\\n" + METHOD + b"\\n" + path + b"\\n" + time + b"\\n" + nonce + b"\\n" + sha256(body).hex()

Headers: ``X-Tgtrust-Agent`` (64 hex), ``X-Tgtrust-Time`` (unix seconds), ``X-Tgtrust-Nonce`` (16–64 chars of
``[A-Za-z0-9_-]``), ``X-Tgtrust-Signature`` (base64url, 64 bytes).
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import threading
import time as _time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import concordium
from .badge import LEVEL_REVOKED, LEVEL_STAKED, LEVEL_UNKNOWN, LEVEL_VERIFIED

SCHEME = "tgtrust-req/v1"
H_AGENT = "X-Tgtrust-Agent"
H_TIME = "X-Tgtrust-Time"
H_NONCE = "X-Tgtrust-Nonce"
H_SIG = "X-Tgtrust-Signature"
HEADERS = (H_AGENT, H_TIME, H_NONCE, H_SIG)
EXTENSION_URI = "https://github.com/miinimal/tgtrust/blob/main/docs/TRUST_GATE.md#x402-extra-v1"

_KEY = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_PATH_MAX = 2048
_METHOD = re.compile(r"^[A-Z]{1,10}$")

BadgeLookup = Callable[[str], dict]
LinkLookup = Callable[[str], concordium.ConcordiumLink]


class GateError(ValueError):
    """A request the gate cannot evaluate (bad header, bad signature, replay). ``code`` is stable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value or ""):
        raise GateError("bad_signature", "signature is not base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:  # pragma: no cover - regex already rejects most input
        raise GateError("bad_signature", "signature is not base64url") from exc


def request_message(method: str, path: str, ts: int, nonce: str, body: bytes) -> bytes:
    """The exact bytes the agent key signs. ``path`` includes the query string, as sent."""
    if not _METHOD.match(method):
        raise GateError("bad_request", "method must be 1-10 upper-case letters")
    if not path.startswith("/") or len(path) > _PATH_MAX or any(c in path for c in "\r\n"):
        raise GateError("bad_request", "path must start with / and be at most 2048 characters on one line")
    if not _NONCE.match(nonce):
        raise GateError("bad_nonce", "nonce must be 16-64 characters of A-Z a-z 0-9 _ -")
    return b"\n".join([
        SCHEME.encode(), method.encode(), path.encode(), str(int(ts)).encode(), nonce.encode(),
        hashlib.sha256(body).hexdigest().encode(),
    ])


def sign_request(agent, method: str, path: str, body: bytes = b"", *, now: int | None = None,
                 nonce: str | None = None) -> dict[str, str]:
    """Client side: headers that prove this request comes from ``agent`` (a ``client.AgentIdentity``)."""
    ts = int(_time.time()) if now is None else int(now)
    nonce = nonce or secrets.token_urlsafe(18)
    msg = request_message(method, path, ts, nonce, body)
    return {H_AGENT: agent.hex, H_TIME: str(ts), H_NONCE: nonce, H_SIG: _b64url(agent.sign(msg))}


class NonceCache:
    """Remembers (agent, nonce) pairs inside the time window, so a captured request cannot be replayed."""

    def __init__(self, window_seconds: int, max_entries: int = 100_000):
        self.window = window_seconds
        self.max_entries = max_entries
        self._seen: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._lock = threading.Lock()

    def use(self, agent: str, nonce: str, now: int) -> bool:
        """True the first time a pair is seen inside the window; False on a replay."""
        with self._lock:
            horizon = now - 2 * self.window
            while self._seen:
                oldest_key, oldest_ts = next(iter(self._seen.items()))
                if oldest_ts >= horizon and len(self._seen) < self.max_entries:
                    break
                self._seen.popitem(last=False)
            key = (agent, nonce)
            if key in self._seen:
                return False
            self._seen[key] = now
            return True


@dataclass(frozen=True)
class Tier:
    """What an agent that reached this tier may do. Amounts are in the API's own smallest unit."""

    name: str
    allowed: bool = True
    prepay: bool = True
    credit_limit: int = 0

    def to_dict(self) -> dict:
        return {"name": self.name, "allowed": self.allowed, "prepay": self.prepay,
                "creditLimit": str(self.credit_limit)}


DENY = Tier("denied", allowed=False)


@dataclass(frozen=True)
class Policy:
    """Maps evidence to a tier. Tiers are checked from the strongest to the weakest; the first one met wins.

    ``require_concordium``: a Concordium network (``testnet``/``mainnet``); then ``concordium_tier`` applies only
    to keys whose CIS-8 binding is Active and whose Verified by Concordium badge is valid.
    """

    anonymous: Tier = Tier("anonymous", prepay=True)
    unknown: Tier = Tier("unknown", prepay=True)
    verified: Tier = Tier("verified", prepay=True)
    staked: Tier = Tier("staked", prepay=True)
    concordium_tier: Tier | None = None
    require_concordium: str | None = None
    min_stake_nanogram: int = 0
    max_upheld_disputes: int = 0


@dataclass
class Decision:
    tier: Tier
    agent: str | None = None
    level: str | None = None
    proven: bool = False
    error: str | None = None
    evidence: list[str] = field(default_factory=list)
    concordium: dict | None = None

    @property
    def allowed(self) -> bool:
        return self.tier.allowed

    def to_dict(self) -> dict:
        return {"agent": self.agent, "level": self.level, "proven": self.proven, "error": self.error,
                "tier": self.tier.to_dict(), "evidence": list(self.evidence), "concordium": self.concordium}


def _header(headers: dict, name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def _upheld(badge: dict) -> int:
    disputes = ((badge.get("history") or {}).get("disputes")) or {}
    value = disputes.get("upheld_against", disputes.get("upheld", 0))
    return value if isinstance(value, int) and value >= 0 else 0


def _stake_amount(badge: dict) -> int:
    stake = badge.get("stake") or {}
    if stake.get("found") is not True or stake.get("withdrawing"):
        return 0
    amount = stake.get("amount_nanogram", stake.get("amount", 0))
    try:
        return max(0, int(amount))
    except (TypeError, ValueError):
        return 0


class TrustGate:
    """Server side. ``badge_lookup(key) -> badge dict`` (for example ``TgTrustClient(url).badge``)."""

    def __init__(self, badge_lookup: BadgeLookup, policy: Policy | None = None, *,
                 link_lookup: LinkLookup | None = None, max_skew_seconds: int = 120,
                 nonces: NonceCache | None = None, clock: Callable[[], float] = _time.time,
                 badge_url: Callable[[str], str] | None = None):
        self.badge_lookup = badge_lookup
        self.policy = policy or Policy()
        if self.policy.require_concordium and link_lookup is None:
            network = self.policy.require_concordium
            link_lookup = lambda key: concordium.read_link(key, concordium.RegistryReader(network))  # noqa: E731
        self.link_lookup = link_lookup
        self.max_skew = max_skew_seconds
        self.nonces = nonces or NonceCache(max_skew_seconds)
        self.clock = clock
        self.badge_url = badge_url

    def verify(self, method: str, path: str, headers: dict, body: bytes = b"") -> str | None:
        """The proven agent key, None when the request carries no tgtrust headers. Raises GateError otherwise."""
        values = {h: _header(headers, h) for h in HEADERS}
        if all(v is None for v in values.values()):
            return None
        missing = [h for h, v in values.items() if not v]
        if missing:
            raise GateError("missing_header", "missing " + ", ".join(missing))
        agent = values[H_AGENT].lower()
        if not _KEY.match(agent):
            raise GateError("bad_agent", "agent key must be 64 hex characters")
        if not re.fullmatch(r"[0-9]{1,12}", values[H_TIME]):
            raise GateError("bad_time", "time must be unix seconds")
        ts = int(values[H_TIME])
        now = int(self.clock())
        if abs(now - ts) > self.max_skew:
            raise GateError("stale", f"request time is more than {self.max_skew} s away from the server clock")
        msg = request_message(method, path, ts, values[H_NONCE], body)
        sig = _unb64url(values[H_SIG])
        if len(sig) != 64:
            raise GateError("bad_signature", "signature must be 64 bytes")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(agent)).verify(sig, msg)
        except (InvalidSignature, ValueError) as exc:
            raise GateError("bad_signature", "signature does not match the agent key and request") from exc
        if not self.nonces.use(agent, values[H_NONCE], now):
            raise GateError("replay", "this nonce was already used by this agent")
        return agent

    def decide(self, method: str, path: str, headers: dict, body: bytes = b"") -> Decision:
        """Never raises for caller mistakes or lookup failures: those become the anonymous or unknown tier."""
        p = self.policy
        try:
            agent = self.verify(method, path, headers, body)
        except GateError as exc:
            return Decision(p.anonymous, error=exc.code, evidence=[f"request signature: rejected ({exc.code})"])
        if agent is None:
            return Decision(p.anonymous, evidence=["request signature: none (anonymous caller)"])
        evidence = [f"request signature: valid for agent key {agent} [{SCHEME}]"]
        try:
            badge = self.badge_lookup(agent)
        except Exception as exc:  # noqa: BLE001 - any lookup failure means nothing was learned
            evidence.append(f"tgtrust badge: lookup failed ({type(exc).__name__}); treated as unknown")
            return Decision(p.unknown, agent=agent, level=LEVEL_UNKNOWN, proven=True, error="badge_lookup",
                            evidence=evidence)
        level = badge.get("level") if isinstance(badge, dict) else None
        if not isinstance(badge, dict) or badge.get("agent", agent) != agent or level not in (
                LEVEL_UNKNOWN, LEVEL_REVOKED, LEVEL_VERIFIED, LEVEL_STAKED):
            evidence.append("tgtrust badge: malformed or for another key; treated as unknown")
            return Decision(p.unknown, agent=agent, level=LEVEL_UNKNOWN, proven=True, error="badge_malformed",
                            evidence=evidence)
        src = f" [source: {self.badge_url(agent)}]" if self.badge_url else " [source: issuer badge]"
        evidence.append(f"tgtrust level: {level}{src}")
        decision = Decision(p.unknown, agent=agent, level=level, proven=True, evidence=evidence)
        if level in (LEVEL_UNKNOWN, LEVEL_REVOKED):
            return decision

        upheld = _upheld(badge)
        if upheld > p.max_upheld_disputes:
            evidence.append(f"disputes upheld against it: {upheld} (policy allows {p.max_upheld_disputes}); "
                            "held at the unknown tier")
            return decision

        decision.tier = p.verified
        stake = _stake_amount(badge)
        if level == LEVEL_STAKED and stake >= p.min_stake_nanogram:
            net = (badge.get("stake") or {}).get("network", "?")
            evidence.append(f"stake: {stake} nanogram active on TON {net}")
            decision.tier = p.staked
        elif level == LEVEL_STAKED:
            evidence.append(f"stake: {stake} nanogram, below the policy minimum {p.min_stake_nanogram}")

        if p.require_concordium and p.concordium_tier is not None and self.link_lookup is not None:
            link = self.link_lookup(agent)
            decision.concordium = {"network": link.network, "account": link.account,
                                   "binding": link.binding_status, "badge": link.badge,
                                   "badgeValid": link.badge_valid, "error": link.error}
            if link.binding_status == "Active" and link.badge_valid is True and not link.error:
                evidence.append(f"Concordium: key bound to {link.account}, badge {link.badge} valid "
                                f"[source: Concordium {link.network} Agent Registry]")
                decision.tier = p.concordium_tier
            else:
                why = link.error or ("not bound" if link.account is None else
                                     f"binding {link.binding_status}, badge valid {link.badge_valid}")
                evidence.append(f"Concordium: not counted ({why})")
        return decision


def x402_extra(decision: Decision, *, issuer_url: str | None = None) -> dict:
    """The ``extra.tgtrust`` object for x402 PaymentRequirements: what this caller gets and how to get more."""
    return {
        "extension": EXTENSION_URI,
        "scheme": SCHEME,
        "headers": list(HEADERS),
        "issuer": issuer_url,
        "agent": decision.agent,
        "level": decision.level,
        "tier": decision.tier.to_dict(),
        "error": decision.error,
    }


EXTENSION_KEY = "tgtrust"

_TIER_SCHEMA = {
    "type": "object",
    "properties": {"name": {"type": "string"}, "allowed": {"type": "boolean"}, "prepay": {"type": "boolean"},
                   "creditLimit": {"type": "string", "pattern": "^[0-9]+$"}},
    "required": ["name", "allowed", "prepay", "creditLimit"],
}

EXTENSION_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "extension": {"type": "string"},
        "scheme": {"const": SCHEME},
        "headers": {"type": "array", "items": {"type": "string"}},
        "issuer": {"type": ["string", "null"]},
        "agent": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"},
        "level": {"type": ["string", "null"]},
        "tier": _TIER_SCHEMA,
        "error": {"type": ["string", "null"]},
    },
    "required": ["extension", "scheme", "headers", "tier"],
}


def x402_extension(decision: Decision, *, issuer_url: str | None = None) -> dict:
    """``{"tgtrust": {"info": ..., "schema": ...}}`` for the top-level ``extensions`` of an x402 v2 PaymentRequired.

    x402 v2 (spec read 2026-11-13) keeps ``accepts[].extra`` for scheme-specific keys and carries protocol
    extensions as ``extensions.<key> = {info, schema}``; use this for v2 and ``x402_extra`` for v1 replies.
    """
    return {EXTENSION_KEY: {"info": x402_extra(decision, issuer_url=issuer_url), "schema": EXTENSION_SCHEMA}}


def gate_for_issuer(issuer_url: str, policy: Policy | None = None, **kwargs) -> TrustGate:
    """A gate that reads badges from a tgtrust issuer, e.g. ``https://trust.example.org/v1``."""
    from .client import TgTrustClient

    client = TgTrustClient(issuer_url)
    base = issuer_url.rstrip("/")
    return TrustGate(client.badge, policy, badge_url=lambda key: f"{base}/agents/{key}/badge", **kwargs)
