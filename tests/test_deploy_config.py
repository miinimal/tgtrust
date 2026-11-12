"""Deploy files and service start-up agree on where the databases live. Offline; PyYAML is not used."""

from __future__ import annotations

import os
import pathlib
import re

import pytest

from tgtrust.keys import write_issuer_key
from tgtrust.service import Settings, create_app

from .conftest import BOT_ID

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVICE_SRC = (ROOT / "tgtrust" / "service.py").read_text()
COMPOSE_SRC = (ROOT / "deploy" / "docker-compose.yml").read_text()

ALL_NAMES = {
    "db_path": "TGTRUST_DB_PATH",
    "registry_db_path": "TGTRUST_REGISTRY_DB_PATH",
    "deals_db_path": "TGTRUST_DEALS_DB_PATH",
    "disputes_db_path": "TGTRUST_DISPUTES_DB_PATH",
}


def db_setting_names() -> set[str]:
    body = SERVICE_SRC.split("def from_env", 1)[1].split("\nclass ", 1)[0]
    return set(re.findall(r"\"(TGTRUST_(?:[A-Z]+_)?DB_PATH)\"", body))


def issuer_environment() -> dict[str, str]:
    block = COMPOSE_SRC.split("\n  issuer:\n", 1)[1]
    block = re.split(r"\n  [A-Za-z_-]+:\n|\n[A-Za-z_-]+:", block, maxsplit=1)[0]
    env_part = block.split("    environment:\n", 1)[1]
    values = {}
    for line in env_part.splitlines():
        match = re.match(r"^      ([A-Z_]+): (\S+)\s*$", line)
        if not match:
            break
        values[match.group(1)] = match.group(2)
    return values


def test_source_scan_finds_the_four_known_names():
    assert db_setting_names() == set(ALL_NAMES.values())


def test_every_database_setting_is_in_the_compose_file_under_data():
    env = issuer_environment()
    for name in sorted(db_setting_names()):
        assert name in env, f"{name} is read by the service but not set in deploy/docker-compose.yml"
        assert env[name].startswith("/data/"), f"{name}={env[name]} is outside the data volume"


def test_the_four_values_are_four_different_files():
    env = issuer_environment()
    values = [env[name] for name in sorted(db_setting_names())]
    assert len(values) == 4
    assert len(set(values)) == 4


def make_settings(tmp_path, **overrides) -> Settings:
    key_path = str(tmp_path / "issuer.pem")
    if not os.path.exists(key_path):
        write_issuer_key(key_path, bits=2048)
    paths = {
        "TGTRUST_DB_PATH": str(tmp_path / "issuer.db"),
        "TGTRUST_REGISTRY_DB_PATH": str(tmp_path / "registry.db"),
        "TGTRUST_DEALS_DB_PATH": str(tmp_path / "deals.db"),
        "TGTRUST_DISPUTES_DB_PATH": str(tmp_path / "disputes.db"),
    }
    paths.update(overrides)
    return Settings.from_env({
        "TGTRUST_BOT_ID": str(BOT_ID),
        "TGTRUST_ISSUER_KEY_FILE": key_path,
        "TGTRUST_PSEUDONYM_KEY": os.urandom(32).hex(),
        **paths,
    })


@pytest.mark.parametrize("name", ["TGTRUST_DISPUTES_DB_PATH", "TGTRUST_DEALS_DB_PATH"])
def test_unopenable_database_stops_the_start_with_a_clear_line(tmp_path, name):
    bad = str(tmp_path / "missing-dir" / "x.db")
    settings = make_settings(tmp_path, **{name: bad})
    with pytest.raises(RuntimeError) as info:
        create_app(settings)
    assert name in str(info.value)
    assert bad in str(info.value)


def test_good_paths_create_exactly_the_four_files(tmp_path):
    create_app(make_settings(tmp_path))
    assert sorted(p.name for p in tmp_path.glob("*.db")) == ["deals.db", "disputes.db", "issuer.db", "registry.db"]
