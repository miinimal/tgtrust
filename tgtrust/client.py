"""Agent-side client for the tgtrust issuer service (standard library only).

One agent = one Ed25519 key. The client walks the whole lifecycle:

    agent = AgentIdentity.generate()                      # or AgentIdentity(private_key_bytes)
    tg = TgTrustClient("https://trust.example.org/v1")
    cred = tg.obtain_credential(agent, init_data)         # init data from the issuer Mini App
    tg.register(agent, cred)                              # badge now shows the Telegram check as passed
    tg.badge(other_agent_hex)                             # what stands behind a counterparty
    deal = tg.propose_deal(agent, other_hex, amount)      # half-signed record to send to the other agent
    tg.submit_deal(deal, other_signature)                 # both signatures -> ledger
    tg.file_dispute(agent, deal_id, other_hex, payout_address, reason_hash)

Command line, for an agent whose owner used the holder Mini App (served by the issuer at /app/):

    python -m tgtrust.client new-key --out agent.key                  # prints the public key to paste
    python -m tgtrust.client register --credential credential.json --key-file agent.key
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .deals import canonical_bytes, order_keys
from .disputes import case_bytes
from .issuer import Credential, Holder, verify_credential
from .registry import agent_token, bind_message


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


AGENT_FILE_FORMAT = "tgtrust-agent/v1"
CREDENTIAL_FILE_FORMAT = "tgtrust-credential/v1"


@dataclass(frozen=True)
class CredentialFile:
    """The ``credential.json`` produced by the holder Mini App: a credential bound to one agent key."""

    issuer: str
    key_id: str
    agent_public_key: bytes
    salt: bytes
    credential: Credential

    @classmethod
    def from_dict(cls, data: dict) -> "CredentialFile":
        if not isinstance(data, dict) or data.get("format") != CREDENTIAL_FILE_FORMAT:
            raise ValueError("not a tgtrust credential file")
        try:
            agent = bytes.fromhex(data["agent_public_key"])
            salt = b64url_decode(data["salt"])
            credential = Credential(b64url_decode(data["token"]), b64url_decode(data["signature"]))
            issuer, key_id = str(data["issuer"]), str(data["key_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("credential file is malformed") from exc
        if len(agent) != 32 or agent_token(agent, salt) != credential.token:
            raise ValueError("credential file is inconsistent: the token is not bound to this agent key")
        return cls(issuer, key_id, agent, salt, credential)

    @classmethod
    def load(cls, path: str) -> "CredentialFile":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        # agent.json wraps the same credential next to the key
        if isinstance(data, dict) and data.get("format") == AGENT_FILE_FORMAT:
            data = data.get("credential")
        return cls.from_dict(data)


class TgTrustError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


@dataclass
class AgentIdentity:
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "AgentIdentity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "AgentIdentity":
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @property
    def public_key(self) -> bytes:
        return self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def hex(self) -> str:
        return self.public_key.hex()

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    @classmethod
    def from_agent_file(cls, path: str) -> "AgentIdentity":
        """Load the ``agent.json`` the holder Mini App shows for a key it created (format tgtrust-agent/v1)."""
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or data.get("format") != AGENT_FILE_FORMAT:
            raise ValueError("not a tgtrust agent file")
        agent = cls.from_bytes(bytes.fromhex(data["agent_private_key"]))
        if agent.hex != data.get("agent_public_key"):
            raise ValueError("agent file is inconsistent: the private key does not match the public key")
        return agent

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )


@dataclass(frozen=True)
class DealProposal:
    """A deal record signed by one party; the other party adds its signature."""

    deal_id: bytes
    key_a: bytes
    key_b: bytes
    amount: int
    created_at: int
    memo_hash: bytes
    message: bytes
    signature: bytes  # by the proposer
    proposer: bytes

    def to_dict(self) -> dict:
        return {
            "deal_id": b64url_encode(self.deal_id),
            "key_a": b64url_encode(self.key_a),
            "key_b": b64url_encode(self.key_b),
            "amount_nanogram": self.amount,
            "created_at": self.created_at,
            "memo_hash": b64url_encode(self.memo_hash),
            "signature": b64url_encode(self.signature),
            "proposer": b64url_encode(self.proposer),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DealProposal":
        deal_id, key_a, key_b = (b64url_decode(d[k]) for k in ("deal_id", "key_a", "key_b"))
        memo = b64url_decode(d["memo_hash"])
        message = canonical_bytes(deal_id, key_a, key_b, d["amount_nanogram"], d["created_at"], memo)
        return cls(deal_id, key_a, key_b, d["amount_nanogram"], d["created_at"], memo, message,
                   b64url_decode(d["signature"]), b64url_decode(d["proposer"]))

    def counter_sign(self, agent: AgentIdentity) -> bytes:
        """The other party checks the proposer's signature, then signs the same bytes."""
        Ed25519PublicKey.from_public_bytes(self.proposer).verify(self.signature, self.message)
        if agent.public_key not in (self.key_a, self.key_b) or agent.public_key == self.proposer:
            raise ValueError("this agent is not the counterparty of the proposal")
        return agent.sign(self.message)


Transport = Callable[[str, str, dict | None], tuple[int, dict]]


def urllib_transport(timeout: float = 20.0) -> Transport:
    def send(method: str, url: str, body: dict | None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", "User-Agent": "tgtrust-client/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode() or "{}")
            except ValueError:
                return exc.code, {}

    return send


class TgTrustClient:
    def __init__(self, base_url: str, *, transport: Transport | None = None):
        self.base_url = base_url.rstrip("/")
        self._send = transport or urllib_transport()

    # --- plumbing ---

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        status, payload = self._send(method, self.base_url + path, body)
        if status >= 400:
            detail = payload.get("detail", {}) if isinstance(payload, dict) else {}
            code = detail.get("code", "error") if isinstance(detail, dict) else str(detail)
            raise TgTrustError(status, code)
        return payload

    # --- identity ---

    def issuer_info(self) -> dict:
        return self._call("GET", "/issuer")

    def obtain_credential(self, agent: AgentIdentity, init_data: str, *, salt: bytes | None = None) -> tuple[Credential, bytes]:
        """Blind-issues a credential bound to this agent's key. Returns (credential, salt)."""
        info = self.issuer_info()
        public_key = serialization.load_pem_public_key(info["public_key_pem"].encode())
        holder = Holder(public_key)
        salt = salt or os.urandom(16)
        req = holder.prepare(agent_token(agent.public_key, salt))
        resp = self._call("POST", "/issue", {"init_data": init_data, "blinded_message": b64url_encode(req.blinded_message)})
        return holder.finalize(req, b64url_decode(resp["blind_signature"])), salt

    def register(self, agent: AgentIdentity, credential: Credential, salt: bytes) -> dict:
        challenge = b64url_decode(self._call("POST", "/challenge")["challenge"])
        return self._call("POST", "/register", {
            "token": b64url_encode(credential.token),
            "signature": b64url_encode(credential.signature),
            "agent_public_key": b64url_encode(agent.public_key),
            "salt": b64url_encode(salt),
            "challenge": b64url_encode(challenge),
            "agent_signature": b64url_encode(agent.sign(bind_message(challenge, credential.token))),
        })

    # --- trust ---

    def badge(self, agent_hex: str) -> dict:
        return self._call("GET", f"/agents/{agent_hex}/badge")

    def deals(self, agent_hex: str, limit: int = 20) -> dict:
        return self._call("GET", f"/agents/{agent_hex}/deals?limit={limit}")

    def disputes(self, agent_hex: str, limit: int = 20) -> dict:
        return self._call("GET", f"/agents/{agent_hex}/disputes?limit={limit}")

    # --- deals ---

    @staticmethod
    def propose_deal(agent: AgentIdentity, counterparty_hex: str, amount_nanogram: int, *,
                     memo_hash: bytes = bytes(32), created_at: int | None = None) -> DealProposal:
        other = bytes.fromhex(counterparty_hex)
        key_a, key_b = order_keys(agent.public_key, other)
        deal_id = os.urandom(16)
        created_at = created_at or int(time.time())
        message = canonical_bytes(deal_id, key_a, key_b, amount_nanogram, created_at, memo_hash)
        return DealProposal(deal_id, key_a, key_b, amount_nanogram, created_at, memo_hash, message,
                            agent.sign(message), agent.public_key)

    def submit_deal(self, proposal: DealProposal, counter_signature: bytes) -> dict:
        other = proposal.key_b if proposal.proposer == proposal.key_a else proposal.key_a
        return self._call("POST", "/deals", {
            "deal_id": b64url_encode(proposal.deal_id),
            "key_x": b64url_encode(proposal.proposer),
            "key_y": b64url_encode(other),
            "amount_nanogram": proposal.amount,
            "created_at": proposal.created_at,
            "memo_hash": b64url_encode(proposal.memo_hash),
            "signature_x": b64url_encode(proposal.signature),
            "signature_y": b64url_encode(counter_signature),
        })

    # --- disputes ---

    def file_dispute(self, agent: AgentIdentity, deal_id: bytes, accused_hex: str, payout_address: str,
                     reason_hash: bytes = bytes(32), *, filed_at: int | None = None) -> dict:
        accused = bytes.fromhex(accused_hex)
        filed_at = filed_at or int(time.time())
        sig = agent.sign(case_bytes(deal_id, agent.public_key, accused, reason_hash, filed_at))
        return self._call("POST", "/disputes", {
            "deal_id": b64url_encode(deal_id),
            "claimant_key": b64url_encode(agent.public_key),
            "accused_key": b64url_encode(accused),
            "reason_hash": b64url_encode(reason_hash),
            "payout_address": payout_address,
            "filed_at": filed_at,
            "claimant_signature": b64url_encode(sig),
        })

    def case(self, case_id: int) -> dict:
        return self._call("GET", f"/disputes/{case_id}")


# --- command line ---


def write_agent_key(path: str) -> AgentIdentity:
    """Create an agent key file readable by its owner only. Refuses to overwrite."""
    agent = AgentIdentity.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(agent.private_bytes().hex() + "\n")
    return agent


def read_agent_key(path: str) -> AgentIdentity:
    with open(path, encoding="ascii") as fh:
        return AgentIdentity.from_bytes(bytes.fromhex(fh.read().strip()))


def register_from_file(credential_path: str, agent: AgentIdentity, *, url: str | None = None,
                       transport: Transport | None = None) -> dict:
    """Check a credential file against the agent key and the issuer, then register the agent."""
    package = CredentialFile.load(credential_path)
    if package.agent_public_key != agent.public_key:
        raise ValueError("this credential is bound to a different agent key")
    client = TgTrustClient(url or package.issuer, transport=transport)
    info = client.issuer_info()
    if info["key_id"] != package.key_id:
        raise ValueError("the issuer key changed since this credential was issued")
    public_key = serialization.load_pem_public_key(info["public_key_pem"].encode())
    if not verify_credential(public_key, package.credential):
        raise ValueError("the credential does not verify with the issuer key")
    return client.register(agent, package.credential, package.salt)


def _cli(argv: list[str] | None = None, *, transport: Transport | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m tgtrust.client", allow_abbrev=False,
                                     description="Agent-side commands for a tgtrust issuer.")
    sub = parser.add_subparsers(dest="command", required=True)
    new_key = sub.add_parser("new-key", allow_abbrev=False, help="create an agent key file and print its public key")
    new_key.add_argument("--out", required=True, help="file to write the private key to (never overwritten)")
    register = sub.add_parser("register", allow_abbrev=False, help="register this agent with a credential file")
    register.add_argument("--credential", required=True, help="credential.json or agent.json from the Mini App")
    register.add_argument("--key-file", help="agent key file made by new-key (not needed with agent.json)")
    register.add_argument("--url", help="issuer API base, if different from the one in the file")
    check = sub.add_parser("check", allow_abbrev=False,
                           help="print the trust card of another agent; exit 0 only if it is verified or staked")
    who = check.add_mutually_exclusive_group(required=True)
    who.add_argument("--agent", help="the other agent's public key, 64 hex characters")
    who.add_argument("--card", help="the other agent's A2A / ERC-8004 card: a file, an https URL, or an https "
                                    "origin (then /.well-known/agent-card.json is read)")
    check.add_argument("--url", default=os.environ.get("TGTRUST_ISSUER_URL"),
                       help="issuer API base, e.g. https://issuer.example/v1 (default: $TGTRUST_ISSUER_URL)")
    check.add_argument("--json", action="store_true", help="print the raw badge JSON instead of the card")
    check.add_argument("--concordium", choices=["testnet", "mainnet"],
                       help="also read the Concordium Agent Registry: is this key bound to an identified account?")
    bind = sub.add_parser("concordium-bind", allow_abbrev=False,
                          help="sign a CIS-8 binding of this agent key to your Concordium account (nothing is sent)")
    bind.add_argument("--key-file", required=True, help="agent key file made by new-key")
    bind.add_argument("--account", required=True, help="your Concordium account address")
    bind.add_argument("--network", choices=["testnet", "mainnet"], default="testnet")
    args = parser.parse_args(argv)

    if args.command == "check":
        return _check(args, transport)
    if args.command == "concordium-bind":
        return _concordium_bind(args)

    try:
        if args.command == "new-key":
            agent = write_agent_key(args.out)
            print(f"Public key: {agent.hex}")
            print(f"Private key written to {args.out}. Keep it on the agent's machine; never paste it anywhere.")
            return 0
        agent = read_agent_key(args.key_file) if args.key_file else AgentIdentity.from_agent_file(args.credential)
        badge = register_from_file(args.credential, agent, url=args.url, transport=transport)
    except FileExistsError:
        print(f"ERROR: {args.out} already exists; refusing to overwrite a key")
        return 1
    except TgTrustError as exc:
        print(f"ERROR: the issuer answered {exc.status} {exc.code}")
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(f"Registered: agent {badge['agent']}, issuer key {badge['issuer_key_id']}")
    return 0


concordium_fetch = None  # tests replace this with a recorded-reply fetcher

WELL_KNOWN_CARD = "/.well-known/agent-card.json"
CARD_MAX_BYTES = 256 * 1024


def _fetch_card(url: str, timeout: float = 10.0) -> bytes:
    import urllib.request

    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "tgtrust-client/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https only, checked by the caller
        data = resp.read(CARD_MAX_BYTES + 1)
    if len(data) > CARD_MAX_BYTES:
        raise ValueError(f"card is larger than {CARD_MAX_BYTES} bytes")
    return data


card_fetch = _fetch_card  # tests replace this


def card_source(card: str) -> tuple[str, bool]:
    """(where to read the card, is it a URL). An https origin gets the A2A well-known path."""
    from urllib.parse import urlsplit

    if "://" not in card:
        return card, False
    parts = urlsplit(card)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError("a card URL must start with https://")
    if parts.path in ("", "/"):
        return f"https://{parts.netloc}{WELL_KNOWN_CARD}", True
    return card, True


def agent_key_from_card(card: dict) -> str:
    """The tgtrust agent key a card claims. Raises ValueError when it names none, a bad one, or two different ones.

    Read from the A2A extension (capabilities.extensions, uri = the tgtrust extension, params.agentKey) and from
    the ERC-8004 file's ``tgtrust.agent_key``. A card is only a claim: it does not prove its host holds the key.
    """
    from .erc8004 import TGTRUST_EXTENSION_URI

    if not isinstance(card, dict):
        raise ValueError("the card is not a JSON object")
    found = []
    caps = card.get("capabilities")
    exts = caps.get("extensions") if isinstance(caps, dict) else None
    for ext in exts if isinstance(exts, list) else []:
        if isinstance(ext, dict) and ext.get("uri") == TGTRUST_EXTENSION_URI:
            params = ext.get("params")
            found.append(params.get("agentKey") if isinstance(params, dict) else None)
    tg = card.get("tgtrust")
    if isinstance(tg, dict) and "agent_key" in tg:
        found.append(tg.get("agent_key"))
    if not found:
        raise ValueError("the card has no tgtrust agent key (no tgtrust extension, no tgtrust.agent_key)")
    keys = set()
    for k in found:
        if not isinstance(k, str) or len(k) != 64 or any(c not in "0123456789abcdef" for c in k.lower()):
            raise ValueError("the card's tgtrust agent key is not 64 hex characters")
        keys.add(k.lower())
    if len(keys) != 1:
        raise ValueError("the card names two different tgtrust agent keys")
    return keys.pop()


def _key_from_card_arg(card: str) -> str:
    where, is_url = card_source(card)
    if is_url:
        raw = card_fetch(where)
    else:
        with open(where, "rb") as fh:
            raw = fh.read(CARD_MAX_BYTES + 1)
        if len(raw) > CARD_MAX_BYTES:
            raise ValueError(f"card is larger than {CARD_MAX_BYTES} bytes")
    return agent_key_from_card(json.loads(raw))


def _concordium_bind(args) -> int:
    from . import concordium

    try:
        agent = read_agent_key(args.key_file)
        request = concordium.binding_request(agent, args.account, args.network)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(json.dumps(request, indent=2))
    print(f"Next: pass this to the Concordium Agent Registry tool build_cis8_register ({concordium.MCP_URL}), "
          f"then sign and submit the returned transaction from account {args.account} in your Concordium wallet. "
          "The signature only proves the agent key agrees to the binding; it moves no funds.", file=sys.stderr)
    return 0


def _check(args, transport: Transport | None) -> int:
    """Exit codes: 0 verified or staked, 2 unknown or revoked, 1 error (bad input, issuer unreachable)."""
    from .badge import LEVEL_STAKED, LEVEL_VERIFIED, card_text

    note = None
    if args.card:
        try:
            key = _key_from_card_arg(args.card)
        except (OSError, ValueError) as exc:
            print(f"ERROR: card: {exc}")
            return 1
        note = (f"Card {args.card} names agent key {key}. A card is only a claim: to know its host holds this key, "
                "have it sign a request (tgtrust.gate, docs/TRUST_GATE.md).")
    else:
        key = args.agent.strip().lower()
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        print("ERROR: --agent must be a 64-character hex public key")
        return 1
    if not args.url:
        print("ERROR: no issuer URL; pass --url or set TGTRUST_ISSUER_URL")
        return 1
    client = TgTrustClient(args.url, transport=transport)
    try:
        badge = client.badge(key)
        latest = None
        if ((badge.get("history") or {}).get("deals") or {}).get("count"):
            items = client.deals(key, limit=1).get("deals") or []
            latest = items[0] if items else None
    except TgTrustError as exc:
        print(f"ERROR: the issuer answered {exc.status} {exc.code}")
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}")
        return 1
    link = None
    if args.concordium:
        from . import concordium
        link = concordium.read_link(key, concordium.RegistryReader(args.concordium, fetch=concordium_fetch))
    if args.json:
        if link is not None:
            badge = {**badge, "concordium": vars(link)}
        if note:
            badge = {**badge, "card_note": note}
        print(json.dumps(badge, indent=2, sort_keys=True))
    else:
        text = card_text(badge, latest)
        if note:
            text = note + "\n" + text
        if link is not None:
            from .concordium import link_lines
            text += "\n" + "\n".join(link_lines(link))
        print(text)
    return 0 if badge.get("level") in (LEVEL_VERIFIED, LEVEL_STAKED) else 2


if __name__ == "__main__":
    raise SystemExit(_cli())
