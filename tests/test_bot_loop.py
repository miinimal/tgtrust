"""Polling round and loop of the badge bot, fully offline."""

import http.client
import io
import json
import urllib.error
from pathlib import Path

import pytest

from tgtrust import bot

ROOT = Path(__file__).resolve().parent.parent / "examples"

TOKEN = "123456:SECRET-token_abc"
API = f"https://api.telegram.org/bot{TOKEN}"
KEY = "ab" * 32


def no_badge(key):
    raise RuntimeError("badge not reachable")


def update(update_id, text="/start", chat_id=7):
    return {"update_id": update_id, "message": {"chat": {"id": chat_id}, "text": text}}


class Recorder:
    def __init__(self, result=None, fail_on=None, fail_with=None):
        self.result = result
        self.fail_on = fail_on or ()
        self.fail_with = fail_with
        self.sent = []
        self.sleeps = []

    def get_json(self, url, timeout=30.0):
        return {"ok": True, "result": self.result}

    def post_json(self, url, payload, timeout=30.0):
        self.sent.append((url, payload))
        if payload["chat_id"] in self.fail_on:
            raise self.fail_with
        return {"ok": True}

    def poll(self, offset=0):
        return bot.poll_once(API, offset, no_badge, None, self.get_json, self.post_json, self.sleeps.append)


def http_403():
    return urllib.error.HTTPError(f"{API}/sendMessage", 403, "Forbidden", {}, io.BytesIO(b""))


@pytest.mark.parametrize(
    "exc",
    [
        http.client.RemoteDisconnected("Remote end closed connection without response"),
        http.client.IncompleteRead(b"abc", 5),
        ConnectionResetError("reset"),
        urllib.error.URLError("down"),
        TimeoutError("timed out"),
        ValueError("bad json"),
    ],
)
def test_get_updates_failure_keeps_offset_and_logs_one_line(exc, capsys):
    sleeps = []

    def get_json(url, timeout=30.0):
        raise exc

    new_offset = bot.poll_once(API, 41, no_badge, None, get_json, lambda *a, **k: {}, sleeps.append)
    assert new_offset == 41
    assert sleeps == [5]
    err = capsys.readouterr().err
    assert len(err.splitlines()) == 1
    assert err.startswith("getUpdates failed")


def test_failed_send_does_not_stop_batch_and_offset_moves_past_all(capsys):
    rec = Recorder(
        result=[update(10, chat_id=1), update(11, chat_id=2), update(12, chat_id=3)],
        fail_on=(2,),
        fail_with=http_403(),
    )
    assert rec.poll(0) == 13
    assert [p["chat_id"] for _, p in rec.sent] == [1, 2, 3]
    err = capsys.readouterr().err
    assert len(err.splitlines()) == 1
    assert err.startswith("sendMessage failed")


@pytest.mark.parametrize(
    "bad",
    [
        {"message": {"chat": {"id": 9}, "text": "/start"}},  # no update_id
        {"update_id": 20, "message": "text"},  # message not an object
        {"update_id": 20, "message": {"text": "/start"}},  # chat missing
        {"update_id": 20, "message": {"chat": {"id": 9}, "text": 5}},  # text not a string
        {"update_id": 20, "message": {"chat": {"id": 9}, "text": ["/start"]}},
        {"update_id": 20, "message": {"chat": "x", "text": "/start"}},
        "not an object",
        None,
    ],
)
def test_unexpected_update_shapes_are_skipped(bad):
    rec = Recorder(result=[bad, update(21, chat_id=5)])
    assert rec.poll(0) == 22
    assert [p["chat_id"] for _, p in rec.sent] == [5]


@pytest.mark.parametrize("result", [None, "x", {"a": 1}, 5])
def test_result_not_a_list_is_skipped(result):
    rec = Recorder(result=result)
    assert rec.poll(3) == 3
    assert rec.sent == []


def test_response_not_an_object_is_skipped():
    sent = []
    out = bot.poll_once(API, 3, no_badge, None, lambda url, timeout=30.0: [1], lambda *a, **k: sent.append(a), lambda s: None)
    assert out == 3 and sent == []


def test_token_in_exception_text_is_masked(capsys):
    def get_json(url, timeout=30.0):
        raise urllib.error.URLError(f"cannot reach {API}/getUpdates")

    bot.poll_once(API, 0, no_badge, None, get_json, lambda *a, **k: {}, lambda s: None)
    err = capsys.readouterr().err
    assert "***" in err
    assert TOKEN not in err


def test_token_in_send_failure_is_masked(capsys):
    rec = Recorder(result=[update(1)], fail_on=(7,), fail_with=OSError(f"failed {API}/sendMessage"))
    rec.poll(0)
    err = capsys.readouterr().err
    assert "***" in err
    assert TOKEN not in err


def test_healthy_round_sends_plain_text_payload():
    calls = []

    def post_json(url, payload, timeout=30.0):
        calls.append((url, payload))
        return {"ok": True}

    badge = json.loads((ROOT / "card" / "badge-alice.json").read_text())
    out = bot.poll_once(
        API,
        0,
        lambda key: badge,
        None,
        lambda url, timeout=30.0: {"result": [update(5, f"/card {KEY}")]},
        post_json,
        lambda s: None,
    )
    assert out == 6
    assert len(calls) == 1
    url, body = calls[0]
    assert url == f"{API}/sendMessage"
    assert set(body) == {"chat_id", "text"}
    assert body["chat_id"] == 7


class Stop(Exception):
    pass


def test_run_continues_after_dropped_connections():
    calls = []

    def get_json(url, timeout=30.0):
        calls.append(url)
        if len(calls) < 3:
            raise http.client.RemoteDisconnected("closed")
        raise Stop

    sleeps = []
    with pytest.raises(Stop):
        bot.run(TOKEN, "http://badge.invalid", get_json, lambda *a, **k: {}, sleeps.append)
    assert len(calls) == 3
    assert sleeps == [5, 5]
