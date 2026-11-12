import json
from pathlib import Path

from tgtrust.badge import card_text
from tgtrust.bot import reply_for

ROOT = Path(__file__).resolve().parent.parent / "examples"


def _demo():
    badge = json.loads((ROOT / "card" / "badge-alice.json").read_text())
    bob = json.loads((ROOT / "card" / "badge-bob.json").read_text())
    deal = json.loads((ROOT / "card" / "deal.json").read_text())
    return badge, bob, deal


def test_card_with_one_confirmed_deal_shows_four_facts_with_sources():
    badge, bob, deal = _demo()
    description = deal.pop("description")
    card = card_text(badge, deal, counterparty_badge=bob, description=description)
    lines = {ln.split(":")[0]: ln for ln in card.splitlines()}
    cp = bob["agent"]
    assert lines["Latest deal id"] == "Latest deal id: " + deal["deal_id"] + " [source: ledger]"
    assert description in lines["Latest deal description"]
    assert "[source: description supplied off-ledger" in lines["Latest deal description"]
    assert cp[:8] + "…" + cp[-4:] in lines["Latest deal counterparty"] and cp not in lines["Latest deal counterparty"]
    assert "badge level verified [source: counterparty badge endpoint]" in lines["Latest deal counterparty"]
    assert "both parties" in lines["Latest deal signatures"] and lines["Latest deal signatures"].endswith("[source: ledger]")
    assert "demo record, local ledger" in card
    assert all("[source:" in ln for ln in card.splitlines() if ln.startswith("Latest deal"))


def test_card_with_zero_deals_is_unchanged_when_deal_passed():
    badge = json.loads((ROOT / "erc8004" / "badge-registered.json").read_text())
    assert card_text(badge, {"deal_id": "x", "parties": []}) == card_text(badge)
    assert "Latest deal" not in card_text(badge)


def test_card_without_deal_record_shows_unknown():
    badge, _, _ = _demo()
    card = card_text(badge)
    for name in ("id", "description", "counterparty", "signatures"):
        assert "Latest deal " + name + ": unknown" in card
    assert "Deals: 1 confirmed deals" in card


def test_description_not_matching_memo_hash_is_unknown_and_counterparty_level_unread():
    badge, _, deal = _demo()
    card = card_text(badge, deal, description="something else")
    assert "Latest deal description: unknown" in card and "something else" not in card
    assert "badge level unknown [source: counterparty badge endpoint]" in card


def test_card_command_reads_deal_through_ledger_path():
    badge, bob, deal = _demo()
    deal.pop("description")
    badges = {badge["agent"]: badge, bob["agent"]: bob}
    reply = reply_for("/card " + badge["agent"], badges.__getitem__, lambda key: {"deals": [deal]})
    assert "Latest deal id: " + deal["deal_id"] in reply and "badge level verified" in reply
    assert "Latest deal description: unknown" in reply  # the ledger keeps only the hash

    def broken(key):
        raise OSError("down")

    assert "Latest deal id: unknown" in reply_for("/card " + badge["agent"], badges.__getitem__, broken)
