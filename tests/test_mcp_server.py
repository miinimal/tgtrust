"""MCP stdio server: protocol handshake, tool listing and the two read-only tools."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient

from tgtrust import Issuer, MemoryIssuedStore
from tgtrust.client import AgentIdentity, TgTrustClient
from tgtrust.mcp_server import Server, serve
from tgtrust.service import create_app

from .conftest import BOT_ID
from .test_concordium import FakeRegistry


@pytest.fixture
def world(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    http = TestClient(create_app(issuer=issuer, rate_limit_per_minute=1000))

    def transport(method, url, body):
        resp = http.request(method, url.replace("http://issuer", ""), json=body)
        return resp.status_code, resp.json()

    return TgTrustClient("http://issuer/v1", transport=transport), transport, telegram


def run(server, *messages):
    out = io.StringIO()
    serve(server, io.StringIO("".join(json.dumps(m) + "\n" for m in messages)), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def call(mid, name, arguments):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}


def test_handshake_and_tool_list():
    replies = run(Server(None),
                  {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                  {"jsonrpc": "2.0", "method": "notifications/initialized"},
                  {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                  {"jsonrpc": "2.0", "id": 3, "method": "nope"})
    assert [r["id"] for r in replies] == [1, 2, 3]  # the notification gets no reply
    assert replies[0]["result"]["serverInfo"]["name"] == "tgtrust"
    assert [t["name"] for t in replies[1]["result"]["tools"]] == ["tgtrust_check_agent", "tgtrust_concordium_link"]
    assert replies[2]["error"]["code"] == -32601


def test_check_agent_unknown_then_verified(world):
    client, transport, telegram = world
    server = Server("http://issuer/v1", transport=transport, concordium_fetch=FakeRegistry(bound=False))
    agent = AgentIdentity.generate()
    first = run(server, call(1, "tgtrust_check_agent", {"agent_key": agent.hex}))[0]["result"]
    assert first["structuredContent"] == {"level": "unknown", "verified": False} and not first["isError"]
    client.register(agent, *client.obtain_credential(agent, telegram.init_data({"id": 77}, auth_date=int(time.time()))))
    second = run(server, call(2, "tgtrust_check_agent", {"agent_key": agent.hex.upper(), "concordium": "testnet"}))
    result = second[0]["result"]
    assert result["structuredContent"]["verified"] is True and result["structuredContent"]["level"] == "verified"
    assert "Badge level: verified" in result["content"][0]["text"]
    assert "not bound to any Concordium account" in result["content"][0]["text"]


def test_bad_input_and_missing_issuer():
    replies = run(Server(None), call(1, "tgtrust_check_agent", {"agent_key": "xyz"}),
                  call(2, "tgtrust_check_agent", {"agent_key": "ab" * 32}),
                  call(3, "unknown_tool", {}))
    assert replies[0]["result"]["isError"] and "64 hex" in replies[0]["result"]["content"][0]["text"]
    assert replies[1]["result"]["isError"] and "TGTRUST_ISSUER_URL" in replies[1]["result"]["content"][0]["text"]
    assert replies[2]["error"]["code"] == -32602


def test_concordium_link_tool():
    server = Server(None, concordium_fetch=FakeRegistry(bound=True))
    result = run(server, call(1, "tgtrust_concordium_link", {"agent_key": "ab" * 32, "network": "testnet"}))[0]["result"]
    assert result["structuredContent"]["badge_valid"] is True
    assert "Concordium badge: JyP9WZqZqhYXTLTYqJYcT, valid" in result["content"][0]["text"]


def test_garbage_line_is_a_parse_error():
    out = io.StringIO()
    serve(Server(None), io.StringIO("not json\n\n"), out)
    assert json.loads(out.getvalue())["error"]["code"] == -32700


def test_runs_as_a_module():
    proc = subprocess.run([sys.executable, "-m", "tgtrust.mcp_server"], capture_output=True, text=True, timeout=30,
                          input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n",
                          env={**os.environ, "TGTRUST_ISSUER_URL": ""})
    assert proc.returncode == 0 and json.loads(proc.stdout)["result"]["tools"][0]["name"] == "tgtrust_check_agent"
