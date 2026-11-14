"""`python -m tgtrust.client sign-request`: an agent proves it holds its key for one request (Trust Desk's challenge)."""

from __future__ import annotations

import json
import time

from tgtrust import gate
from tgtrust.client import _cli, read_agent_key

PATH = "/trust-desk/v1/challenge/abcDEF0123456789_-xy"


def test_signed_challenge_verifies_with_the_gate(tmp_path, capsys):
    key_file = tmp_path / "agent.key"
    assert _cli(["new-key", "--out", str(key_file)]) == 0
    capsys.readouterr()
    assert _cli(["sign-request", "--key-file", str(key_file), "--path", PATH]) == 0
    out, err = capsys.readouterr()
    headers = json.loads(out)
    assert set(headers) == set(gate.HEADERS)
    agent = read_agent_key(str(key_file))
    assert headers[gate.H_AGENT] == agent.hex
    assert "private" not in out.lower() and agent.private_bytes().hex() not in out
    assert "contain no private key" in err
    g = gate.TrustGate(lambda k: {}, clock=time.time)
    assert g.verify("POST", PATH, headers, b"") == agent.hex


def test_body_and_method_are_signed(tmp_path, capsys):
    key_file = tmp_path / "agent.key"
    _cli(["new-key", "--out", str(key_file)])
    body = tmp_path / "body.json"
    body.write_bytes(b'{"q":1}')
    capsys.readouterr()
    assert _cli(["sign-request", "--key-file", str(key_file), "--method", "PUT", "--path", "/v1/x?y=1",
                 "--body-file", str(body)]) == 0
    headers = json.loads(capsys.readouterr().out)
    g = gate.TrustGate(lambda k: {}, clock=time.time)
    assert g.verify("PUT", "/v1/x?y=1", headers, b'{"q":1}')
    try:
        gate.TrustGate(lambda k: {}, clock=time.time).verify("PUT", "/v1/x?y=1", headers, b'{"q":2}')
    except gate.GateError as exc:
        assert exc.code == "bad_signature"
    else:
        raise AssertionError("a changed body must not verify")


def test_bad_input_is_an_error_not_a_signature(tmp_path, capsys):
    key_file = tmp_path / "agent.key"
    _cli(["new-key", "--out", str(key_file)])
    capsys.readouterr()
    assert _cli(["sign-request", "--key-file", str(key_file), "--path", "no-slash"]) == 1
    assert _cli(["sign-request", "--key-file", str(key_file), "--method", "post", "--path", "/x"]) == 1
    assert _cli(["sign-request", "--key-file", str(tmp_path / "missing.key"), "--path", "/x"]) == 1
    assert "X-Tgtrust-Signature" not in capsys.readouterr().out
