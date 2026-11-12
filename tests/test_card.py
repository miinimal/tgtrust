import json
from pathlib import Path

from tgtrust.badge import card_text
from tgtrust.bot import HELP, reply_for

EX = Path(__file__).resolve().parent.parent / "examples" / "erc8004"


def load(name):
    return json.loads((EX / name).read_text())


def test_registered_agent_card():
    card = card_text(load("badge-registered.json"))
    assert card.startswith("AGENT CARD c92220c3…1551")
    assert "Registration: registered" in card and "issuer key 455ab7792859f113" in card
    assert "Stake: none on TON testnet" in card
    assert "Deals: 0 confirmed deals" in card


def test_unregistered_agent_card():
    card = card_text(load("badge-demo-staked-unregistered.json"))
    assert card.startswith("AGENT CARD 738559c1…28d8")
    assert "not registered" in card
    assert "Stake: 0.4 GRAM on TON testnet" in card
    assert "read 2026-" in card


def test_zero_deals_is_not_unknown():
    badge = load("badge-registered.json")
    zero = card_text(badge)
    assert "0 confirmed deals" in zero and "Deals: unknown" not in zero
    badge["history"]["deals"] = None
    badge["stake"] = {"network": "testnet", "contract": "C", "found": None, "error": "timeout"}
    unknown = card_text(badge)
    assert "Deals: unknown" in unknown and "0 confirmed deals" not in unknown
    assert "Stake: unknown" in unknown and "Stake: none" not in unknown
    badge["stake"] = None
    assert "Stake: unknown" in card_text(badge)


def test_every_statement_names_its_source_and_limits_are_stated():
    for name in ("badge-registered.json", "badge-demo-staked-unregistered.json"):
        card = card_text(load(name))
        body = [ln for ln in card.splitlines() if not ln.startswith(("AGENT CARD", "Key:"))]
        assert body and all("[source:" in ln for ln in body)
        for src in ("badge endpoint", "ledger", "TON testnet stake read, read "):
            assert src in card

def test_telegram_check_line_registered_vs_unregistered():
    reg = card_text(load("badge-registered.json"))
    assert ("Telegram check: issuer credential, one Telegram account per issuer epoch. "
            "Owner identity is not checked and not revealed. [source: badge endpoint]") in reg
    assert "not performed" not in reg
    unreg = card_text(load("badge-demo-staked-unregistered.json"))
    assert "Telegram check: not performed (agent is not registered). [source: badge endpoint]" in unreg
    assert "issuer credential" not in unreg and "one Telegram account" not in unreg


def test_card_command_and_help_wording():
    badge = load("badge-registered.json")
    reply = reply_for("/card " + badge["agent"], lambda key: badge)
    assert reply == card_text(badge)
    assert "unique owner" not in HELP.lower() and "accountable" not in HELP.lower()
    assert "/card" in HELP
