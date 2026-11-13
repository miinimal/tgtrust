"""Concordium Agent Registry link: bind a tgtrust agent key to a Concordium account and read it back.

Concordium's Agent Registry (docs.concordium.com, Technical reference > Agent Registry, read 2026-11-13) has two
contracts: CIS-8004 mints each agent as a CIS-2 token (the "Verified by Concordium" badge is that token's address),
and CIS-8 records a proven binding between a Concordium account and an external public key. Every Concordium
account is opened with an identity from an identity provider, so an account is tied to an identified person
without revealing who.

tgtrust agent keys are Ed25519, which CIS-8 accepts (key type ``ed25519``, scheme ``solana-ed25519``: the external
key signs the canonical bytes directly). After the owner registers the binding from his Concordium wallet, anyone
can go from a tgtrust agent key to its Concordium account and badge, and combine:

- Concordium: an identified person controls the account that owns this key (no name disclosed);
- tgtrust: one Telegram account per issuer epoch, TON stake, co-signed deals and dispute record.

This module never holds a Concordium key and never sends a transaction. ``binding_request`` produces the
arguments for the registry's ``build_cis8_register`` tool; the owner signs and submits the result in his wallet.
"""

from __future__ import annotations

import hashlib
import json
import struct
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

NAMESPACE = "tgtrust:v1"          # CAIP-2 shaped: namespace "tgtrust", reference "v1" (tgtrust is not a chain)
KEY_TYPE = "ed25519"
SCHEME = "solana-ed25519"         # CIS-8: «signs the canonical bytes directly with ed25519»
CANONICAL_PREFIX = b"CIS-8/v1/canonical"
MCP_URL = "https://agent-registry-mcp.concordium.com/mcp"
BADGE_CHECK_URL = "https://agent-registry-mcp.concordium.com/v1/badge-check/"


@dataclass(frozen=True)
class Network:
    name: str
    genesis_hash: str        # hex, 32 bytes
    cis8: tuple[int, int]
    cis8004: tuple[int, int]
    explorer: str


# Values read from the registry's contract_info / build_cis8_canonical_bytes tools on 2026-11-13.
NETWORKS = {
    "testnet": Network("testnet", "4221332d34e1694168c2a0c0b3fd0f273809612cb13d000d5c2e00e85f50f796",
                       (12801, 0), (12802, 0), "https://testnet.ccdscan.io"),
    "mainnet": Network("mainnet", "9dd9ca4d19e9393877d2c44b70f89acbfc0883c2243e5eeaecc0d1cd0503f478",
                       (10081, 0), (10082, 0), "https://ccdscan.io"),
}

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class ConcordiumError(Exception):
    pass


def account_bytes(address: str) -> bytes:
    """Decode a Concordium account address (Base58Check, version byte 1) to its 32 bytes."""
    address = address.strip()
    if not 40 <= len(address) <= 60 or any(c not in _B58 for c in address):
        raise ValueError("not a Concordium account address")
    n = 0
    for c in address:
        n = n * 58 + _B58.index(c)
    raw = n.to_bytes(37, "big") if n.bit_length() <= 37 * 8 else b""
    if len(raw) != 37 or raw[0] != 1:
        raise ValueError("not a Concordium account address")
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise ValueError("Concordium account address checksum does not match")
    return raw[1:33]


def _lp(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def canonical_bytes(account: str, agent_public_key_hex: str, network: str = "testnet") -> bytes:
    """The bytes the agent key signs for CIS-8 ``register``.

    Layout, matched byte for byte against the registry's ``build_cis8_canonical_bytes`` (tests/golden):
    prefix | account (32) | CIS-8 contract index, subindex (u64 LE each) | genesis hash (32) |
    namespace | key namespace | key type | public key | scheme, each u32 LE length + bytes."""
    net = NETWORKS[network]
    key = bytes.fromhex(agent_public_key_hex)
    if len(key) != 32:
        raise ValueError("agent public key must be 32 bytes")
    ns = NAMESPACE.encode()
    return (CANONICAL_PREFIX + account_bytes(account) + struct.pack("<QQ", *net.cis8) + bytes.fromhex(net.genesis_hash)
            + _lp(ns) + _lp(ns) + _lp(KEY_TYPE.encode()) + _lp(key) + _lp(SCHEME.encode()))


def external_key(agent_public_key_hex: str) -> dict:
    return {"namespace": NAMESPACE, "key_type": KEY_TYPE, "public_key_hex": agent_public_key_hex.lower()}


def binding_request(agent, account: str, network: str = "testnet") -> dict:
    """Arguments for the registry's ``build_cis8_register`` tool, signed by the agent key.

    ``agent`` is a ``tgtrust.client.AgentIdentity``. The owner passes this to the registry (MCP tool or DApp),
    then signs and submits the returned transaction with the Concordium account ``account``."""
    signature = agent.sign(canonical_bytes(account, agent.hex, network))
    return {"network": network, "sender": account, "external_key": external_key(agent.hex),
            "proof": {"scheme": SCHEME, "signature_hex": signature.hex()}}


# --- reading the registry -------------------------------------------------------------------------------

Fetch = Callable[[str, str, bytes | None, dict], tuple[int, bytes]]


def urllib_fetch(timeout: float = 20.0) -> Fetch:
    def fetch(method: str, url: str, body: bytes | None, headers: dict) -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": "tgtrust/0.1", **headers})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    return fetch


class RegistryReader:
    """Read-only client for Concordium's hosted Agent Registry service (MCP over HTTP + badge-check REST)."""

    def __init__(self, network: str = "testnet", *, fetch: Fetch | None = None, mcp_url: str = MCP_URL,
                 badge_check_url: str = BADGE_CHECK_URL):
        if network not in NETWORKS:
            raise ValueError(f"unknown network {network!r}")
        self.network = network
        self._fetch = fetch or urllib_fetch()
        self._mcp_url = mcp_url
        self._badge_url = badge_check_url

    def _tool(self, name: str, arguments: dict):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": name, "arguments": {"network": self.network, **arguments}}}).encode()
        status, raw = self._fetch("POST", self._mcp_url, body, {"Content-Type": "application/json",
                                                                 "Accept": "application/json, text/event-stream"})
        if status != 200:
            raise ConcordiumError(f"registry answered HTTP {status}")
        text = raw.decode("utf-8", "replace")
        if text.lstrip().startswith("event:") or text.lstrip().startswith("data:"):
            text = next((ln[5:] for ln in text.splitlines() if ln.startswith("data:")), "{}")
        try:
            reply = json.loads(text)
            result = reply["result"]
            content = result["content"][0]["text"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ConcordiumError("registry reply has an unexpected shape") from exc
        if result.get("isError"):
            raise ConcordiumError(f"registry tool error: {content[:200]}")
        try:
            return json.loads(content)
        except ValueError as exc:
            raise ConcordiumError(f"registry tool error: {content[:200]}") from exc

    def owner_of_key(self, agent_public_key_hex: str) -> tuple[str, str] | None:
        """(Concordium account, binding status) for this tgtrust key's CIS-8 binding, or None if unbound."""
        reply = self._tool("owner_of_key", {"external_key": external_key(agent_public_key_hex)})
        if reply is None:
            return None
        owner = reply.get("owner") if isinstance(reply, dict) else None
        if not isinstance(owner, str):
            raise ConcordiumError("registry reply has an unexpected shape")
        account_bytes(owner)  # validates the address
        return owner, str(reply.get("status") or "unknown")

    def agent_for_key(self, agent_public_key_hex: str) -> dict | None:
        """CIS-8004 agent that carries this key as its CIS-8 external reference, or None."""
        index, sub = NETWORKS[self.network].cis8
        return self._tool("agent_by_external_reference", {"external_reference": {
            "contract_address": {"index": index, "subindex": sub}, "kind": "Cis8",
            "key": external_key(agent_public_key_hex)}})

    def agents_of(self, account: str) -> list:
        reply = self._tool("agents_by_owner", {"owner_account": account})
        if isinstance(reply, dict):
            reply = reply.get("agents") or []
        return reply if isinstance(reply, list) else []

    def badge_check(self, badge: str) -> dict:
        """The registry's verdict on a badge (token address): on-chain record, card hash, checks."""
        if not badge or any(c not in _B58 for c in badge):
            raise ValueError("not a badge token address")
        url = self._badge_url + urllib.parse.quote(badge) + "?network=" + self.network
        status, raw = self._fetch("GET", url, None, {"Accept": "application/json"})
        if status != 200:
            raise ConcordiumError(f"badge check answered HTTP {status}")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise ConcordiumError("badge check reply is not JSON") from exc


@dataclass
class ConcordiumLink:
    network: str
    account: str | None = None
    binding_status: str | None = None
    badge: str | None = None
    badge_valid: bool | None = None
    status: str | None = None
    error: str | None = None


def read_link(agent_public_key_hex: str, reader: RegistryReader) -> ConcordiumLink:
    """Key -> CIS-8 owner account -> that key's CIS-8004 agent -> badge check. Never raises on network errors."""
    link = ConcordiumLink(reader.network)
    try:
        bound = reader.owner_of_key(agent_public_key_hex)
        if bound is None:
            return link
        link.account, link.binding_status = bound
        if link.binding_status != "Active":
            return link
        agent = reader.agent_for_key(agent_public_key_hex)
        token = agent.get("token_address") if isinstance(agent, dict) else None
        if token:
            link.badge = token
            verdict = reader.badge_check(token)
            link.badge_valid = bool(verdict.get("badge_valid"))
            link.status = (verdict.get("on_chain") or {}).get("status")
            owner = (verdict.get("on_chain") or {}).get("owner_account")
            if owner and owner != link.account:
                link.badge_valid = False
                link.error = "badge owner is a different account than the key binding"
    except (ConcordiumError, OSError, ValueError) as exc:
        link.error = str(exc) or type(exc).__name__
    return link


def link_lines(link: ConcordiumLink) -> list[str]:
    src = f"[source: Concordium {link.network} Agent Registry, CIS-8 / CIS-8004]"
    if link.error and link.account is None:
        return [f"Concordium: unknown, the read failed ({link.error[:80]}) {src}"]
    if link.account is None:
        return [f"Concordium: this key is not bound to any Concordium account {src}"]
    short = f"{link.account[:6]}…{link.account[-4:]}"
    if link.binding_status != "Active":
        return [f"Concordium: binding to account {short} is {link.binding_status}, not active {src}"]
    lines = [f"Concordium: key bound to account {short} (accounts are opened only "
             f"with an identity from an identity provider; the person is not disclosed) {src}"]
    if link.badge is None:
        lines.append(f"Concordium badge: none for this key {src}" if not link.error
                     else f"Concordium badge: unknown ({link.error[:80]}) {src}")
    else:
        state = "valid" if link.badge_valid else "NOT valid"
        why = f", {link.error[:80]}" if link.error else ""
        lines.append(f"Concordium badge: {link.badge}, {state} (status {link.status or 'unknown'}{why}) {src}")
    return lines


# --- badge for the agent card ----------------------------------------------------------------------------

BADGE_EXTENSION_URI = "https://docs.concordium.com/a2a-extensions/concordium-badge/v1"


def verified_badge(agent_public_key_hex: str, token_address: str, reader: RegistryReader) -> dict:
    """Read a Concordium badge from the chain and accept it only if it belongs to this tgtrust key.

    Checks: the CIS-8004 agent is Active; its CIS-8 external reference is exactly this key (namespace tgtrust:v1,
    ed25519); the key's CIS-8 binding is Active and owned by the same account as the agent. Returns the registry's
    extension object and ERC-8004 ``registrations`` entry, plus what was read. Raises ConcordiumError otherwise.
    The card-hash check is not done here: the card is the file being produced, hosted later."""
    key = agent_public_key_hex.lower()
    got = reader._tool("get_badge_json", {"token_address": token_address})
    if not isinstance(got, dict) or "extension" not in got or "registrations_entry" not in got:
        raise ConcordiumError("badge not found in the registry")
    if got.get("status") != "Active":
        raise ConcordiumError(f"badge status is {got.get('status')}, not Active")
    ext = got["extension"]
    if ext.get("uri") != BADGE_EXTENSION_URI:
        raise ConcordiumError("unexpected badge extension URI")
    ref = (ext.get("params") or {}).get("externalReference") or {}
    if (ref.get("kind"), ref.get("namespace"), ref.get("keyType"), str(ref.get("publicKey", "")).lower()) != (
            "Cis8", NAMESPACE, KEY_TYPE, key):
        raise ConcordiumError("the badge's external reference is not this tgtrust key")
    bound = reader.owner_of_key(key)
    if bound is None or bound[1] != "Active":
        raise ConcordiumError("this key has no active CIS-8 binding")
    if bound[0] != got.get("owner_account"):
        raise ConcordiumError("badge owner is a different account than the key binding")
    entry = got["registrations_entry"]
    if not isinstance(entry.get("agentId"), int) or not str(entry.get("agentRegistry", "")).startswith("ccd:"):
        raise ConcordiumError("unexpected registrations entry")
    return {"extension": ext, "registrations_entry": entry, "network": reader.network,
            "token_address": token_address, "owner_account": got["owner_account"]}
