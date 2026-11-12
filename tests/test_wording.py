"""One wording for the Telegram check: a single source of truth, no `unique_owner` in human-readable output."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from tgtrust import badge as badge_module
from tgtrust import erc8004
from tgtrust.badge import (LEVEL_NAMES, STAKE_PREFIX, TELEGRAM_CHECK_LABEL, TELEGRAM_CHECK_LINE,
                           TELEGRAM_CHECK_MEANING, TELEGRAM_CHECK_SCOPE, card_text)
from tgtrust.bot import HELP

ROOT = Path(__file__).resolve().parents[1]
CARD_DIR = ROOT / "examples" / "card"
ERC_DIR = ROOT / "examples" / "erc8004"

JSON_KEY = re.compile(r'^\s*"unique_owner"\s*:')


def _bad_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if "unique_owner" in ln and not JSON_KEY.match(ln)]


def _run(args: list[str]) -> str:
    done = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr
    return done.stdout + done.stderr


def test_card_and_export_docs_share_one_constant():
    card = card_text(json.loads((CARD_DIR / "badge-alice.json").read_text()))
    assert TELEGRAM_CHECK_LINE in card
    assert TELEGRAM_CHECK_LINE == f"{TELEGRAM_CHECK_LABEL}: {TELEGRAM_CHECK_MEANING}"
    assert TELEGRAM_CHECK_MEANING.startswith(TELEGRAM_CHECK_SCOPE)
    # the export documents the same sentence, taken from the same constant
    assert erc8004.ONE_ACCOUNT_FIELD_MEANING is TELEGRAM_CHECK_SCOPE
    assert TELEGRAM_CHECK_SCOPE in (ROOT / "docs" / "ERC8004_EXPORT.md").read_text()
    # help text uses it too
    assert TELEGRAM_CHECK_LINE in HELP
    for level in LEVEL_NAMES:
        assert level in HELP
    assert STAKE_PREFIX == "Stake: " and badge_module.TELEGRAM_CHECK_LIMITS == TELEGRAM_CHECK_LINE


def test_legacy_field_is_documented_once():
    doc = (ROOT / "docs" / "ERC8004_EXPORT.md").read_text()
    assert doc.count("### Legacy field name `unique_owner`") == 1


def test_no_unique_owner_in_human_readable_output():
    outputs = [
        card_text(json.loads((CARD_DIR / name).read_text()))
        for name in ("badge-alice.json", "badge-bob.json")
    ]
    outputs.append(HELP)
    outputs.append(_run(["-m", "tgtrust.erc8004", "--badge", "examples/erc8004/badge-registered.json",
                         "--profile", "examples/erc8004/profile.json"]))
    outputs.append(_run(["examples/two_agents.py"]))
    for out in outputs:
        assert _bad_lines(out) == []
        assert "unique owner" not in out.lower()


def test_docs_do_not_claim_unique_owner():
    for name in ("README.md", "docs/VERIFY_IN_60_SECONDS.md", "docs/ERC8004_EXPORT.md"):
        text = (ROOT / name).read_text().lower()
        assert "unique owner" not in text, name


CLAIM_PHRASES = ("real telegram user", "real person", "accountable person", "one human")
NEGATIONS = ("not ", "never ", "no ", "n't ", "does not", "cannot")


def _claim_lines(text: str) -> list[str]:
    bad = []
    for ln in text.splitlines():
        low = ln.lower()
        for phrase in CLAIM_PHRASES:
            at = low.find(phrase)
            # a phrase is allowed only when the same line denies it ("It is not one human")
            if at != -1 and not any(n in low[:at] for n in NEGATIONS):
                bad.append(ln)
    return bad


def test_docs_do_not_claim_a_real_or_accountable_person():
    files = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    assert len(files) > 5
    for path in files:
        assert _claim_lines(path.read_text()) == [], path.name


def test_claim_detector_catches_the_old_sentences():
    assert _claim_lines("One real Telegram user backs this agent")
    assert _claim_lines("backed by a real, accountable person")
    assert _claim_lines("an accountable person stands behind it")
    assert _claim_lines("proves one human")
    assert _claim_lines("It is not one human") == []


def test_readme_and_master_prompt_use_the_badge_scope():
    assert "one Telegram account per issuer epoch" in TELEGRAM_CHECK_SCOPE
    names = [n for n in ("README.md", "docs/MASTER_PROMPT.md") if (ROOT / n).exists()]  # the plan is not in every tree
    assert "README.md" in names
    for name in names:
        text = " ".join((ROOT / name).read_text().split())
        assert "one Telegram account per issuer epoch" in text, name
        assert "owner identity is not checked" in text.lower(), name
