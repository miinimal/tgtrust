"""Settings.from_env: every wrong value is reported by name, secrets are never echoed."""

import inspect
import pathlib
import re

import pytest

from tgtrust.service import Settings

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEY = "ab" * 32
BASE = {"TGTRUST_BOT_ID": "123456", "TGTRUST_ISSUER_KEY_FILE": "issuer.pem", "TGTRUST_PSEUDONYM_KEY": KEY}


def env(**extra):
    return {**BASE, **extra}


def invalid(**extra):
    with pytest.raises(RuntimeError) as info:
        Settings.from_env(env(**extra))
    text = str(info.value)
    assert text.startswith("invalid settings: ")
    return text


def test_defaults_with_only_required():
    s = Settings.from_env(dict(BASE))
    assert s == Settings(
        bot_id=123456,
        issuer_key_file="issuer.pem",
        pseudonym_key=bytes.fromhex(KEY),
        db_path="tgtrust.db",
        registry_db_path="tgtrust-registry.db",
        deals_db_path="tgtrust-deals.db",
        disputes_db_path="tgtrust-disputes.db",
        arbiter_public_key="",
        telegram_env="production",
        require_premium=False,
        epoch="v1",
        rate_limit_per_minute=20,
        trust_forwarded_for=False,
        stake_contract="",
        ton_network="testnet",
        toncenter_api_key="",
        stake_cache_seconds=30,
    )


def test_every_field_from_correct_values():
    arbiter = "cd" * 32
    s = Settings.from_env(
        env(
            TGTRUST_DB_PATH="a.db",
            TGTRUST_REGISTRY_DB_PATH="b.db",
            TGTRUST_DEALS_DB_PATH="c.db",
            TGTRUST_DISPUTES_DB_PATH="d.db",
            TGTRUST_ARBITER_PUBLIC_KEY=arbiter,
            TGTRUST_TELEGRAM_ENV="test",
            TGTRUST_REQUIRE_PREMIUM="1",
            TGTRUST_EPOCH="v2",
            TGTRUST_RATE_LIMIT="5",
            TGTRUST_TRUST_FORWARDED_FOR="1",
            TGTRUST_STAKE_CONTRACT="kQ-contract",
            TGTRUST_TON_NETWORK="mainnet",
            TGTRUST_TONCENTER_API_KEY="tc-key",
            TGTRUST_STAKE_CACHE_SECONDS="0",
        )
    )
    assert s == Settings(
        bot_id=123456,
        issuer_key_file="issuer.pem",
        pseudonym_key=bytes.fromhex(KEY),
        db_path="a.db",
        registry_db_path="b.db",
        deals_db_path="c.db",
        disputes_db_path="d.db",
        arbiter_public_key=arbiter,
        telegram_env="test",
        require_premium=True,
        epoch="v2",
        rate_limit_per_minute=5,
        trust_forwarded_for=True,
        stake_contract="kQ-contract",
        ton_network="mainnet",
        toncenter_api_key="tc-key",
        stake_cache_seconds=0,
    )


@pytest.mark.parametrize(
    "name,value",
    [
        ("TGTRUST_REQUIRE_PREMIUM", "true"),
        ("TGTRUST_TRUST_FORWARDED_FOR", "true"),
        ("TGTRUST_RATE_LIMIT", "0"),
        ("TGTRUST_RATE_LIMIT", "-5"),
        ("TGTRUST_TELEGRAM_ENV", "prod"),
        ("TGTRUST_BOT_ID", "abc"),
        ("TGTRUST_BOT_ID", "123456:AAF-secret"),
        ("TGTRUST_BOT_ID", "0"),
        ("TGTRUST_PSEUDONYM_KEY", "zz" * 32),
        ("TGTRUST_PSEUDONYM_KEY", "ab"),
        ("TGTRUST_RATE_LIMIT", "x"),
        ("TGTRUST_STAKE_CACHE_SECONDS", "x"),
        ("TGTRUST_STAKE_CACHE_SECONDS", "-1"),
        ("TGTRUST_ARBITER_PUBLIC_KEY", "hello"),
        ("TGTRUST_ARBITER_PUBLIC_KEY", "abcd"),
        ("TGTRUST_TON_NETWORK", "main"),
    ],
)
def test_table_rows(name, value):
    assert name in invalid(**{name: value})


def test_bot_token_hint_and_no_leak():
    text = invalid(TGTRUST_BOT_ID="123456:AAF-secret")
    assert "bot token" in text
    assert "AAF-secret" not in text
    assert "123456" not in text


def test_bad_pseudonym_key_not_echoed():
    assert "zz" not in invalid(TGTRUST_PSEUDONYM_KEY="zz" * 32)


def test_short_pseudonym_key_not_echoed():
    assert "abab" not in invalid(TGTRUST_PSEUDONYM_KEY="abab")


def test_toncenter_key_never_in_error():
    text = invalid(TGTRUST_TONCENTER_API_KEY="tc-secret", TGTRUST_RATE_LIMIT="0")
    assert "tc-secret" not in text


def test_three_wrong_at_once():
    text = invalid(TGTRUST_BOT_ID="abc", TGTRUST_RATE_LIMIT="0", TGTRUST_TELEGRAM_ENV="prod")
    for name in ("TGTRUST_BOT_ID", "TGTRUST_RATE_LIMIT", "TGTRUST_TELEGRAM_ENV"):
        assert name in text
    assert text.count("; ") == 2


def test_reason_texts():
    assert "use 1 or 0" in invalid(TGTRUST_REQUIRE_PREMIUM="yes")
    text = invalid(TGTRUST_TELEGRAM_ENV="prod")
    assert "production" in text and "test" in text


@pytest.mark.parametrize("name", ["TGTRUST_REQUIRE_PREMIUM", "TGTRUST_TRUST_FORWARDED_FOR"])
class TestFlags:
    def field(self, name):
        return "require_premium" if name.endswith("PREMIUM") else "trust_forwarded_for"

    def test_on(self, name):
        assert getattr(Settings.from_env(env(**{name: "1"})), self.field(name)) is True

    @pytest.mark.parametrize("value", ["0", ""])
    def test_off(self, name, value):
        assert getattr(Settings.from_env(env(**{name: value})), self.field(name)) is False

    def test_absent(self, name):
        assert getattr(Settings.from_env(dict(BASE)), self.field(name)) is False

    @pytest.mark.parametrize("value", ["true", "yes", "on", "2"])
    def test_wrong(self, name, value):
        text = invalid(**{name: value})
        assert name in text and "use 1 or 0" in text


def test_rate_limit_bounds():
    assert Settings.from_env(env(TGTRUST_RATE_LIMIT="1")).rate_limit_per_minute == 1
    for bad in ("0", "-5"):
        invalid(TGTRUST_RATE_LIMIT=bad)


def test_spaces_are_ignored():
    s = Settings.from_env(
        env(
            TGTRUST_BOT_ID=" 123456 ",
            TGTRUST_PSEUDONYM_KEY=KEY + " ",
            TGTRUST_REQUIRE_PREMIUM=" 1 ",
            TGTRUST_RATE_LIMIT=" 7 ",
            TGTRUST_TELEGRAM_ENV=" test ",
            TGTRUST_ARBITER_PUBLIC_KEY=" " + "cd" * 32 + " ",
        )
    )
    assert s.bot_id == 123456
    assert s.pseudonym_key == bytes.fromhex(KEY)
    assert s.require_premium is True
    assert s.rate_limit_per_minute == 7
    assert s.telegram_env == "test"
    assert s.arbiter_public_key == "cd" * 32


def test_arbiter_key_empty_ok():
    assert Settings.from_env(env(TGTRUST_ARBITER_PUBLIC_KEY="")).arbiter_public_key == ""


def test_documented_settings_are_in_deploy_files():
    source = inspect.getsource(Settings.from_env)
    names = {n for n in re.findall(r"TGTRUST_[A-Z_]+", source) if not n.endswith("DB_PATH")}
    assert names
    deployed = (ROOT / "deploy" / "env.example").read_text() + (ROOT / "deploy" / "docker-compose.yml").read_text()
    missing = sorted(n for n in names if n not in deployed)
    assert not missing


def test_missing_still_reported_first():
    with pytest.raises(RuntimeError, match=r"^missing settings: "):
        Settings.from_env({})
    with pytest.raises(RuntimeError, match=r"^missing settings: TGTRUST_BOT_ID"):
        Settings.from_env({"TGTRUST_ISSUER_KEY_FILE": "x", "TGTRUST_PSEUDONYM_KEY": "zz", "TGTRUST_RATE_LIMIT": "0"})
