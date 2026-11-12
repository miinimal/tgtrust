"""The holder Mini App flow end to end: the page's own code (run under Node) against a live service.

A real HTTP server is started on a local port; the JavaScript does everything a browser would do
(load the issuer, blind, ask, unblind, optionally register), and Python checks the result with its own
verifier and the registry. Skipped when Node 20+ is not installed."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from tgtrust import Credential, Issuer, MemoryIssuedStore, verify_credential
from tgtrust.client import AgentIdentity, TgTrustClient, b64url_decode
from tgtrust.registry import agent_token
from tgtrust.service import WEBAPP_DIR, WEBAPP_FILES, create_app

from .conftest import BOT_ID

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node is not installed")

ANN = {"id": 9001, "first_name": "Ann"}
BEN = {"id": 9002, "first_name": "Ben"}


class Live:
    """The service on 127.0.0.1 with a stand-in Telegram key, plus a fresh Node flow process per test."""

    def __init__(self, issuer_key, telegram, **policy):
        from tgtrust import IssuerPolicy

        self.telegram = telegram
        self.issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(), policy=IssuerPolicy(**policy),
                             telegram_public_key_hex=telegram.public_key_hex)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        config = uvicorn.Config(create_app(issuer=self.issuer, rate_limit_per_minute=1000), log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [sock]}, daemon=True)
        self.thread.start()
        while not self.server.started:
            time.sleep(0.01)
        self.origin = f"http://127.0.0.1:{self.port}"
        self.base = self.origin + "/v1/"
        self.node = subprocess.Popen([NODE, str(ROOT / "tests" / "webapp" / "flow_cli.mjs")], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True, cwd=ROOT)

    def js(self, **cmd) -> dict:
        cmd.setdefault("base", self.base)
        self.node.stdin.write(json.dumps(cmd) + "\n")
        self.node.stdin.flush()
        return json.loads(self.node.stdout.readline())

    def init_data(self, user, **kw) -> str:
        return self.telegram.init_data(user, auth_date=int(time.time()), **kw)

    def close(self) -> None:
        self.node.stdin.close()
        self.node.wait(timeout=10)
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture
def live(issuer_key, telegram):
    app = Live(issuer_key, telegram)
    yield app
    app.close()


def credential_of(package: dict) -> Credential:
    return Credential(b64url_decode(package["token"]), b64url_decode(package["signature"]))


def test_issuer_is_loaded_and_checked(live):
    out = live.js(op="issuer")
    assert out["ok"] and out["epoch"] == "v1" and out["require_premium"] is False
    assert len(out["key_id"]) == 16


def test_own_agent_key_credential_registers_from_the_agent_side(live):
    agent = AgentIdentity.generate()
    assert live.js(op="prepare", agent=agent.hex)["ok"]
    out = live.js(op="issue", init_data=live.init_data(ANN))
    assert out["ok"], out
    package = out["package"]
    assert package["format"] == "tgtrust-credential/v1" and package["agent_public_key"] == agent.hex
    assert "seed" not in package and out["record"]["seed"] is None
    # the record no longer holds the blinding secret
    assert out["record"]["inverse"] is None and out["record"]["blinded"] is None

    credential = credential_of(package)
    assert verify_credential(live.issuer.public_key, credential)
    assert credential.token == agent_token(agent.public_key, b64url_decode(package["salt"]))
    # the agent (Python client, holding the private key) registers with the package from the page
    client = TgTrustClient(live.base)
    assert client.register(agent, credential, b64url_decode(package["salt"]))["agent"] == agent.hex
    assert client.badge(agent.hex)["unique_owner"] is True


def test_new_agent_key_is_created_and_registered_in_the_page(live):
    assert live.js(op="ed25519")["supported"] is True
    prepared = live.js(op="prepare")
    seed = bytes.fromhex(prepared["record"]["seed"])
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert prepared["record"]["agent"] == public.hex()  # the seed shown to the holder really is this agent's key
    assert live.js(op="issue", init_data=live.init_data(ANN))["ok"]
    done = live.js(op="register")
    assert done["ok"] and done["record"]["registered"] is True
    badge = TgTrustClient(live.base).badge(public.hex())
    assert badge["unique_owner"] is True
    # registering again (answer lost, holder presses the button twice) ends in the same state
    assert live.js(op="register")["record"]["registered"] is True


def test_lost_answer_is_recovered_by_asking_again(live):
    agent = AgentIdentity.generate()
    live.js(op="prepare", agent=agent.hex)
    lost = live.js(op="issue", init_data=live.init_data(ANN), drop_answer=True)
    assert lost["ok"] is False and lost["code"] == "network"
    # the issuer has recorded the account; the saved request is still there and still unfinished
    saved = live.js(op="pending")["record"]
    assert saved["signature"] is None and saved["blinded"]
    again = live.js(op="issue", init_data=live.init_data(ANN))
    assert again["ok"], again
    assert verify_credential(live.issuer.public_key, credential_of(again["package"]))


def test_second_credential_for_the_account_is_refused(live):
    live.js(op="prepare", agent=AgentIdentity.generate().hex)
    assert live.js(op="issue", init_data=live.init_data(ANN))["ok"]
    live.js(op="clear")
    live.js(op="prepare", agent=AgentIdentity.generate().hex)
    out = live.js(op="issue", init_data=live.init_data(ANN))
    assert out["ok"] is False and out["code"] == "already_issued" and out["status"] == 409
    # another account is unaffected
    live.js(op="clear")
    live.js(op="prepare", agent=AgentIdentity.generate().hex)
    assert live.js(op="issue", init_data=live.init_data(BEN))["ok"]


def test_errors_reach_the_page_as_codes(live, issuer_key, telegram):
    live.js(op="prepare", agent=AgentIdentity.generate().hex)
    forged = live.init_data(ANN).replace("Ann", "Eve")
    assert live.js(op="issue", init_data=forged)["code"] == "invalid_init_data"
    stale = telegram.init_data(ANN, auth_date=int(time.time()) - 10_000)
    assert live.js(op="issue", init_data=stale)["code"] == "invalid_init_data"
    assert live.js(op="issue", init_data=live.init_data({"id": 7, "first_name": "B", "is_bot": True}))["code"] == "bot_account"
    assert live.js(op="issue", init_data="x" * 9000)["code"] == "invalid_request"
    assert live.js(op="issue", init_data=live.init_data(ANN), base="http://127.0.0.1:9/v1/")["code"] == "network"
    assert live.js(op="prepare", agent="zz")["code"] == "bad_agent_key"
    # none of the failures used up the account
    assert live.js(op="issue", init_data=live.init_data(ANN))["ok"]


def test_premium_policy_is_reported(issuer_key, telegram):
    app = Live(issuer_key, telegram, require_premium=True)
    try:
        assert app.js(op="issuer")["require_premium"] is True
        app.js(op="prepare", agent=AgentIdentity.generate().hex)
        assert app.js(op="issue", init_data=app.init_data(ANN))["code"] == "premium_required"
        assert app.js(op="issue", init_data=app.init_data({**ANN, "is_premium": True}))["ok"]
    finally:
        app.close()


def test_saved_record_validation(live):
    assert live.js(op="put", raw="not json")["record"] is None
    assert live.js(op="put", raw=json.dumps({"v": 2}))["record"] is None
    assert live.js(op="put", raw=json.dumps({"v": 1, "token": "a", "agent": "b"}))["record"] is None  # nothing to finish with
    assert live.js(op="register")["ok"] is False


def test_webapp_files_are_served_with_safe_headers(live):
    import urllib.error
    import urllib.request

    for name, content_type in WEBAPP_FILES.items():
        with urllib.request.urlopen(f"{live.origin}/app/{name}") as resp:
            assert resp.status == 200 and resp.headers["Content-Type"] == content_type
            assert resp.headers["Cache-Control"] == "no-store"
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert resp.headers["Referrer-Policy"] == "no-referrer"
            assert resp.read() == (WEBAPP_DIR / name).read_bytes()
    with urllib.request.urlopen(f"{live.origin}/app/") as resp:
        assert resp.read() == (WEBAPP_DIR / "holder.html").read_bytes()
    for name in ("issuer.py", "..%2Fservice.py", "holder.html.bak", "%2e%2e/%2e%2e/pyproject.toml"):
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"{live.origin}/app/{name}")
        assert exc.value.code == 404


def test_every_served_file_exists_and_nothing_else_is_in_the_folder():
    assert sorted(p.name for p in WEBAPP_DIR.iterdir()) == sorted(WEBAPP_FILES)
