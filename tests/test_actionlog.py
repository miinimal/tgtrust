import dataclasses
import json

import pytest

from tgtrust import actionlog as al
from tgtrust.client import AgentIdentity


class Clock:
    def __init__(self, t=1_794_000_000):
        self.t = t

    def __call__(self):
        self.t += 5
        return self.t


def _log(n=4):
    agent = AgentIdentity.generate()
    log = al.ActionLog(agent, clock=Clock())
    for i in range(n):
        log.append("tool.call", f"input {i}", f"output {i}")
    return agent, log


def test_written_log_verifies_and_round_trips():
    agent, log = _log()
    entries = al.loads(log.dumps())
    assert al.verify(entries, agent.hex) == log.head
    assert [e.seq for e in entries] == [0, 1, 2, 3] and entries[0].prev == "00" * 32
    assert entries[1].prev == entries[0].hash and entries[0].input == al.digest("input 0")
    assert al.find(entries, "output 2") == [2] and al.find(entries, "never logged") == []


def test_reopened_log_continues_the_chain():
    agent, log = _log(2)
    again = al.ActionLog(agent, al.loads(log.dumps()), clock=Clock(2_000_000_000))
    again.append("payment", b"x", b"y")
    assert al.verify(again.entries) == again.head and again.entries[2].prev == log.head


def test_signed_bytes_layout():
    a = "ab" * 32
    raw = al.signed_bytes(a, 1, 2, "k", "11" * 32, "22" * 32, "33" * 32)
    assert raw == (b"tgtrust/v1/action:" + bytes.fromhex(a) + (1).to_bytes(8, "big") + (2).to_bytes(8, "big")
                   + b"\x01k" + bytes.fromhex("11" * 32) + bytes.fromhex("22" * 32) + bytes.fromhex("33" * 32))


def _edit(entries, i, **changes):
    out = list(entries)
    out[i] = dataclasses.replace(out[i], **changes)
    return out


@pytest.mark.parametrize("break_it,code,seq", [
    (lambda es: _edit(es, 1, output=al.digest("something else")), "signature", 1),
    (lambda es: es[:1] + es[2:], "seq", 1),                       # an entry removed
    (lambda es: [es[0], es[2], es[1], es[3]], "seq", 1),          # reordered
    (lambda es: es + [es[3]], "seq", 4),                          # repeated
    (lambda es: _edit(es, 2, time=0), "time", 2),
    (lambda es: _edit(es, 0, sig=bytes(64)), "signature", 0),
])
def test_any_change_is_caught_at_the_first_broken_entry(break_it, code, seq):
    agent, log = _log()
    with pytest.raises(al.LogError) as err:
        al.verify(break_it(log.entries), agent.hex)
    assert (err.value.code, err.value.seq) == (code, seq)


def test_rewritten_entry_with_a_valid_signature_breaks_the_chain():
    agent, log = _log()
    forged = al.ActionLog(agent, clock=Clock())
    for i in range(4):
        forged.append("tool.call", f"input {i}", "rewritten" if i == 1 else f"output {i}")
    mixed = log.entries[:1] + forged.entries[1:2] + log.entries[2:]
    assert al.verify(forged.entries) == forged.head          # a full rewrite is self-consistent...
    with pytest.raises(al.LogError) as err:
        al.verify(mixed)
    assert err.value.code == "chain" and err.value.seq == 2   # ...but splicing it into the real log is not
    with pytest.raises(al.LogError, match="rewritten"):       # and the anchor catches the full rewrite
        al.check_anchor(forged.entries, al.parse_anchor(al.anchor_data(agent.hex, 3, log.head)))


def test_other_agent_key_is_rejected():
    _, log = _log()
    with pytest.raises(al.LogError) as err:
        al.verify(log.entries, AgentIdentity.generate().hex)
    assert err.value.code == "other_agent"


def test_anchor_bytes_round_trip_and_fit_register_data():
    agent, log = _log()
    data = al.anchor_data(agent.hex, 3, log.head)
    assert len(data) == 86 <= 256 and data.startswith(b"tgtrust-log/v1")
    anchor = dataclasses.replace(al.parse_anchor(data), tx="ab" * 32, block_time=log.entries[3].time)
    assert (anchor.agent, anchor.seq, anchor.entry_hash) == (agent.hex, 3, log.head)
    assert "entries 0..3 match" in al.check_anchor(log.entries, anchor)
    log.append("later", "a", "b")                              # growing after the anchor is fine
    assert "entries 0..3 match" in al.check_anchor(log.entries, anchor)
    with pytest.raises(al.LogError) as err:
        al.check_anchor(log.entries[:3], anchor)
    assert err.value.code == "anchor_missing"


def test_entry_dated_after_its_anchor_block_is_rejected():
    agent, log = _log()
    anchor = dataclasses.replace(al.parse_anchor(al.anchor_data(agent.hex, 3, log.head)),
                                 block_time=log.entries[3].time - 3600)
    with pytest.raises(al.LogError) as err:
        al.check_anchor(log.entries, anchor)
    assert err.value.code == "anchor_time"


@pytest.mark.parametrize("line", [
    "{}", '{"v": 2}', "not json",
    json.dumps({"v": 1, "agent": "ab" * 32, "seq": 0, "time": 1, "kind": "Bad Kind", "input": "00" * 32,
                "output": "00" * 32, "prev": "00" * 32, "sig": "A" * 86}),
    json.dumps({"v": 1, "agent": "ab" * 32, "seq": -1, "time": 1, "kind": "k", "input": "00" * 32,
                "output": "00" * 32, "prev": "00" * 32, "sig": "A" * 86}),
    json.dumps({"v": 1, "agent": "ab" * 32, "seq": 0, "time": 1, "kind": "k", "input": "00" * 32,
                "output": "00" * 32, "prev": "00" * 32, "sig": "A" * 86, "note": "x"}),
])
def test_malformed_lines_are_rejected(line):
    with pytest.raises(al.LogError) as err:
        al.loads(line)
    assert err.value.code == "malformed"


PAYER = "34vXzUxLshXWmn4U2wf33AZi1eWuxKi36J7CouJEMiuC4ohS4P"
# the demo log and its real anchor on Concordium testnet (examples/action_log), recorded 2026-11-13
DEMO = "examples/action_log/demo-log.jsonl"
DEMO_TX = "3c4c112e733a110e0cce1b758fd717a4b21ca1efdb021f5268fd17d40a6feaf9"
DEMO_DATA = ("746774727573742d6c6f672f7631dbc55639df6bfeef7366bd3c0436d0b75842ff63c3701625d818cbb7022aee26"
             "000000000000000229e75b437dd171c1699dd03d04914190c734eb2dbebb02abccf5eec289539d2f")


def _proxy(pages):
    calls = []

    def fetch(method, url, body, headers):
        calls.append(url)
        return 200, json.dumps(pages[len(calls) - 1]).encode()
    return fetch, calls


def _tx(i, h, kind="registerData", data=DEMO_DATA):
    return {"id": i, "transactionHash": h, "blockTime": 1.794612100069e9,
            "details": {"type": kind, "outcome": "success", "registeredData": data}}


def test_demo_log_matches_its_recorded_anchor():
    from pathlib import Path

    entries = al.loads((Path(__file__).parent.parent / DEMO).read_text(encoding="utf-8"))
    fetch, calls = _proxy([{"limit": 1000, "transactions": [_tx(3269025, DEMO_TX)]}])
    anchor = al.read_anchor(DEMO_TX, PAYER, fetch=fetch)
    assert anchor.block_time == 1794612100 and anchor.seq == 2
    assert "entries 0..2 match" in al.check_anchor(entries, anchor)
    assert calls == [f"https://wallet-proxy.testnet.concordium.com/v1/accTransactions/{PAYER}?limit=1000&order=d"]


def test_read_anchor_pages_and_rejects_other_transactions():
    other = "cd" * 32
    fetch, calls = _proxy([{"limit": 2, "transactions": [_tx(9, other), _tx(8, "ef" * 32)]},
                           {"limit": 2, "transactions": [_tx(7, DEMO_TX)]}])
    assert al.read_anchor(DEMO_TX, PAYER, fetch=fetch).seq == 2 and calls[1].endswith("&from=8")
    fetch, _ = _proxy([{"limit": 1000, "transactions": [_tx(1, other, kind="transfer")]}])
    with pytest.raises(al.LogError, match="not a successful RegisterData"):
        al.read_anchor(other, PAYER, fetch=fetch)
    fetch, _ = _proxy([{"limit": 1000, "transactions": []}])
    with pytest.raises(al.LogError, match="not found"):
        al.read_anchor(DEMO_TX, PAYER, fetch=fetch)


def test_all_anchors_of_the_account_are_checked():
    agent, log = _log()
    first = al.anchor_data(agent.hex, 1, log.entries[1].hash).hex()
    forged = al.ActionLog(agent, clock=Clock())
    for i in range(4):
        forged.append("tool.call", f"input {i}", "rewritten" if i == 0 else f"output {i}")
    late = al.anchor_data(agent.hex, 3, forged.head).hex()
    pages = [{"limit": 1000, "transactions": [
        _tx(5, "05" * 32, data=late), _tx(4, "04" * 32, data="aa"), _tx(3, "03" * 32, data=DEMO_DATA),
        _tx(2, "02" * 32, kind="transfer"), _tx(1, "01" * 32, data=first)]}]
    fetch, _ = _proxy(pages)
    anchors = al.read_anchors(PAYER, agent.hex, fetch=fetch)
    assert [a.seq for a in anchors] == [1, 3]                  # other agents' anchors and other data skipped
    with pytest.raises(al.LogError) as err:                   # the rewritten log matches the late anchor only
        al.check_anchors(forged.entries, anchors)
    assert err.value.code == "anchor_mismatch" and err.value.seq == 1
    with pytest.raises(al.LogError, match="no anchor"):
        al.check_anchors(log.entries, [])


def test_bad_anchor_bytes():
    with pytest.raises(ValueError):
        al.parse_anchor(b"tgtrust-log/v1" + bytes(10))
    with pytest.raises(ValueError):
        al.parse_anchor(b"x" * 86)
