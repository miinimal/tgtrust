"""stake.http_fetcher with urllib.request.urlopen patched: no network."""

import http.client
import io
import json
import urllib.error
import urllib.request

import pytest

from tgtrust.stake import StakeLookupError, http_fetcher

URL = "https://toncenter.invalid/api/v2/runGetMethod"
PAYLOAD = {"address": "EQ", "method": "get_stake", "stack": []}


class FakeResponse:
    def __init__(self, body=b'{"ok": true}', read_exc=None):
        self._body = body
        self._read_exc = read_exc

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        if self._read_exc:
            raise self._read_exc
        return self._body


def patch_urlopen(monkeypatch, behaviour):
    seen = []

    def fake(req, timeout=None):
        seen.append(req)
        if isinstance(behaviour, BaseException):
            raise behaviour
        return behaviour

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    return seen


def test_http_500(monkeypatch):
    exc = urllib.error.HTTPError(URL, 500, "err", {}, io.BytesIO(b""))
    patch_urlopen(monkeypatch, exc)
    with pytest.raises(StakeLookupError, match="toncenter HTTP 500"):
        http_fetcher()(URL, PAYLOAD)


@pytest.mark.parametrize(
    "exc",
    [urllib.error.URLError("down"), http.client.RemoteDisconnected("closed"), TimeoutError("t"), OSError("o")],
)
def test_errors_on_open(monkeypatch, exc):
    patch_urlopen(monkeypatch, exc)
    with pytest.raises(StakeLookupError, match="toncenter unreachable"):
        http_fetcher()(URL, PAYLOAD)


@pytest.mark.parametrize(
    "exc", [ConnectionResetError("reset"), http.client.IncompleteRead(b"a", 3), http.client.RemoteDisconnected("c")]
)
def test_errors_during_read(monkeypatch, exc):
    patch_urlopen(monkeypatch, FakeResponse(read_exc=exc))
    with pytest.raises(StakeLookupError, match="toncenter unreachable"):
        http_fetcher()(URL, PAYLOAD)


def test_body_not_json(monkeypatch):
    patch_urlopen(monkeypatch, FakeResponse(body=b"<html>"))
    with pytest.raises(StakeLookupError):
        http_fetcher()(URL, PAYLOAD)


def test_request_shape_with_and_without_api_key(monkeypatch):
    seen = patch_urlopen(monkeypatch, FakeResponse())
    assert http_fetcher(api_key="k")(URL, PAYLOAD) == {"ok": True}
    assert http_fetcher()(URL, PAYLOAD) == {"ok": True}
    with_key, without_key = seen
    assert with_key.get_method() == "POST"
    assert json.loads(with_key.data) == PAYLOAD
    assert with_key.get_header("X-api-key") == "k"
    assert without_key.get_method() == "POST"
    assert json.loads(without_key.data) == PAYLOAD
    assert not without_key.has_header("X-api-key")
