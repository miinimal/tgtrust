"""The real-check command, run on strings signed with the local stand-in key."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

from tgtrust.telegram_sig import _cli

from .conftest import BOT_ID, NOW

ROOT = Path(__file__).resolve().parents[1]
USER = {"id": 918273645, "first_name": "Zelda", "last_name": "Quux", "username": "zq_secret"}


def run(telegram, tmp_path, capsys, data, *, bot_id=BOT_ID, extra=(), now=NOW + 30):
    path = tmp_path / "init.txt"
    path.write_text(data)
    code = _cli(["--init-data-file", str(path), "--bot-id", str(bot_id), *extra],
                public_key_hex=telegram.public_key_hex, now=now)
    return code, capsys.readouterr().out


def test_valid(telegram, tmp_path, capsys):
    data = telegram.init_data(USER)
    code, out = run(telegram, tmp_path, capsys, data)
    assert code == 0
    assert out == "VALID: user id present, auth_date 2027-01-15T08:00:00Z, age 30 s\n"
    for secret in ("918273645", "Zelda", "Quux", "zq_secret", data, "signature="):
        assert secret not in out


def test_expired(telegram, tmp_path, capsys):
    code, out = run(telegram, tmp_path, capsys, telegram.init_data(USER), now=NOW + 5000)
    assert code == 1 and out == "INVALID: init data has expired\n"
    code, _ = run(telegram, tmp_path, capsys, telegram.init_data(USER), now=NOW + 5000, extra=["--max-age", "6000"])
    assert code == 0


def test_tampered(telegram, tmp_path, capsys):
    code, out = run(telegram, tmp_path, capsys, telegram.init_data(USER).replace("Zelda", "Eve"))
    assert code == 1 and out == "INVALID: signature does not match\n"
    assert "Zelda" not in out and "Eve" not in out


def test_wrong_bot_id(telegram, tmp_path, capsys):
    code, out = run(telegram, tmp_path, capsys, telegram.init_data(USER), bot_id=BOT_ID + 1)
    assert code == 1 and out == "INVALID: signature does not match\n"


def test_missing_signature_field(telegram, tmp_path, capsys):
    data = "&".join(p for p in telegram.init_data(USER).split("&") if not p.startswith("signature="))
    code, out = run(telegram, tmp_path, capsys, data)
    assert code == 1 and out == "INVALID: signature field is missing\n"


def test_empty_and_missing_file(telegram, tmp_path, capsys):
    code, out = run(telegram, tmp_path, capsys, "  \n")
    assert code == 1 and out.startswith("INVALID: init data file is empty")
    code = _cli(["--init-data-file", str(tmp_path / "nope"), "--bot-id", "1"])
    assert code == 1 and capsys.readouterr().out.startswith("INVALID: cannot read")


def test_real_command_uses_published_key_and_prints_one_line(telegram, tmp_path):
    """Run as the owner would: a string signed by the stand-in key must be refused by the published keys."""
    data = telegram.init_data(USER)
    path = tmp_path / "init.txt"
    path.write_text(data)
    for env in ("production", "test"):
        done = subprocess.run(
            [sys.executable, "-m", "tgtrust.telegram_sig", "--init-data-file", str(path),
             "--bot-id", str(BOT_ID), "--env", env],
            cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert done.returncode == 1
        assert done.stdout == "INVALID: signature does not match\n"
        assert done.stderr == ""
        assert data not in done.stdout and "918273645" not in done.stdout


def test_data_is_never_taken_from_argv():
    with pytest.raises(SystemExit):
        _cli(["--init-data", "user=x", "--bot-id", "1"])


def test_miniapp_page_has_no_external_scripts_and_no_network():
    html = (ROOT / "miniapp" / "index.html").read_text()
    assert re.findall(r'<script[^>]*\ssrc="([^"]+)"', html) == ["https://telegram.org/js/telegram-web-app.js"]
    for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "localStorage", "sessionStorage",
                      "indexedDB", "document.cookie", "import("):
        assert forbidden not in html
    assert "Copy init data" in html and "app.initData" in html
    assert "--tg-theme-bg-color" in html and "color-scheme: light dark" in html
    assert 'name="viewport"' in html
