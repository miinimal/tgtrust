"""MCP server (stdio): lets any MCP client (Claude, Cursor, OpenClaw, LangChain…) check an agent before a deal.

    TGTRUST_ISSUER_URL=https://<issuer>/v1 python -m tgtrust.mcp_server

Tools (read-only; nothing is signed or sent):

- ``tgtrust_check_agent``: the trust card of an agent key from the issuer, optionally with the Concordium
  Agent Registry link; returns the level and whether it counts as verified;
- ``tgtrust_concordium_link``: only the Concordium part (CIS-8 binding and badge) of an agent key.

Speaks JSON-RPC 2.0, one message per line (MCP stdio transport, protocol version 2025-06-18).
"""

from __future__ import annotations

import json
import os
import sys
from typing import Callable

from . import concordium
from .badge import LEVEL_STAKED, LEVEL_VERIFIED, card_text
from .client import TgTrustClient, TgTrustError, Transport

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "tgtrust", "version": "0.1.0"}
_KEY_SCHEMA = {"type": "string", "pattern": "^[0-9a-fA-F]{64}$",
               "description": "the other agent's tgtrust public key, 64 hex characters"}
_NET_SCHEMA = {"type": "string", "enum": ["testnet", "mainnet"]}

TOOLS = [
    {"name": "tgtrust_check_agent",
     "description": ("Check another AI agent before a deal, payment or data share: is its key backed by one Telegram "
                     "account at this issuer, does it have a TON stake, what deals and disputes does it have. "
                     "Optionally also reads Concordium's Agent Registry. verified=false means do not treat it as "
                     "verified. Never pay only because of this result; ask your human."),
     "inputSchema": {"type": "object", "properties": {"agent_key": _KEY_SCHEMA, "concordium": _NET_SCHEMA},
                     "required": ["agent_key"], "additionalProperties": False}},
    {"name": "tgtrust_concordium_link",
     "description": ("Is this tgtrust agent key bound (CIS-8) to a Concordium account, which is opened only with an "
                     "identity from an identity provider, and is its Verified by Concordium badge valid?"),
     "inputSchema": {"type": "object", "properties": {"agent_key": _KEY_SCHEMA, "network": _NET_SCHEMA},
                     "required": ["agent_key"], "additionalProperties": False}},
]


class Server:
    def __init__(self, issuer_url: str | None, *, transport: Transport | None = None,
                 concordium_fetch: concordium.Fetch | None = None):
        self.issuer_url = issuer_url
        self._transport = transport
        self._ccd_fetch = concordium_fetch

    def _link(self, key: str, network: str) -> concordium.ConcordiumLink:
        return concordium.read_link(key, concordium.RegistryReader(network, fetch=self._ccd_fetch))

    def check_agent(self, args: dict) -> tuple[str, dict, bool]:
        key = _key(args)
        if not self.issuer_url:
            return "No issuer configured: set TGTRUST_ISSUER_URL for the server.", {"verified": False}, True
        client = TgTrustClient(self.issuer_url, transport=self._transport)
        try:
            badge = client.badge(key)
            latest = None
            if ((badge.get("history") or {}).get("deals") or {}).get("count"):
                items = client.deals(key, limit=1).get("deals") or []
                latest = items[0] if items else None
        except TgTrustError as exc:
            return f"The issuer answered {exc.status} {exc.code}. Nothing was learned.", {"verified": False}, True
        except (OSError, ValueError, KeyError) as exc:
            return f"Issuer unreachable ({type(exc).__name__}). Nothing was learned.", {"verified": False}, True
        text = card_text(badge, latest)
        data = {"level": badge.get("level"), "verified": badge.get("level") in (LEVEL_VERIFIED, LEVEL_STAKED)}
        if args.get("concordium"):
            link = self._link(key, args["concordium"])
            text += "\n" + "\n".join(concordium.link_lines(link))
            data["concordium"] = vars(link)
        return text, data, False

    def concordium_link(self, args: dict) -> tuple[str, dict, bool]:
        link = self._link(_key(args), args.get("network") or "mainnet")
        return "\n".join(concordium.link_lines(link)), vars(link), False

    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:  # notification (e.g. notifications/initialized): no reply
            return None
        if method == "initialize":
            return _ok(mid, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                             "serverInfo": SERVER_INFO})
        if method == "ping":
            return _ok(mid, {})
        if method == "tools/list":
            return _ok(mid, {"tools": TOOLS})
        if method == "tools/call":
            params = msg.get("params") or {}
            handlers: dict[str, Callable] = {"tgtrust_check_agent": self.check_agent,
                                             "tgtrust_concordium_link": self.concordium_link}
            fn = handlers.get(params.get("name"))
            if fn is None:
                return _err(mid, -32602, f"unknown tool {params.get('name')!r}")
            try:
                text, data, is_error = fn(params.get("arguments") or {})
            except ValueError as exc:
                text, data, is_error = f"Invalid input: {exc}", {}, True
            return _ok(mid, {"content": [{"type": "text", "text": text}], "structuredContent": data,
                             "isError": is_error})
        return _err(mid, -32601, f"method not found: {method}")


def _key(args: dict) -> str:
    key = str(args.get("agent_key", "")).strip().lower()
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise ValueError("agent_key must be 64 hex characters")
    for name in ("concordium", "network"):
        if args.get(name) not in (None, "testnet", "mainnet"):
            raise ValueError(f"{name} must be testnet or mainnet")
    return key


def _ok(mid, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(server: Server, stdin=None, stdout=None) -> None:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            reply = server.handle(msg) if isinstance(msg, dict) else _err(None, -32600, "invalid request")
        except ValueError:
            reply = _err(None, -32700, "parse error")
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve(Server(os.environ.get("TGTRUST_ISSUER_URL")))
