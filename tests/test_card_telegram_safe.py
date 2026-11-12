import hashlib
import json
from pathlib import Path

import pytest

from tgtrust import bot
from tgtrust.badge import (DROP_ORDER, PROTECTED_PREFIXES, TELEGRAM_MESSAGE_LIMIT, card_text, fit_card,
                           shortened_notice)

ROOT = Path(__file__).resolve().parent.parent / "examples"
GOLDEN = Path(__file__).resolve().parent / "golden"
SPECIAL = "_ * [ ] ( ) ~ ` > # + - = | { } . ! < & \\ \" '"


def _demo():
    badge = json.loads((ROOT / "card" / "badge-alice.json").read_text())
    bob = json.loads((ROOT / "card" / "badge-bob.json").read_text())
    deal = json.loads((ROOT / "card" / "deal.json").read_text())
    return badge, bob, deal


def _tg_len(text):
    return len(text.encode("utf-16-le")) // 2


def _worst_case(description, note="n" * 4000):
    badge, bob, deal = _demo()
    deal.pop("description", None)
    deal["memo_hash"] = hashlib.sha256(description.encode()).hexdigest()
    deal["note"] = note
    badge["issuer_key_id"] = "k" * 500
    badge["stake"] = dict(network="n" * 500, contract="EQ" + "C" * 2000, found=True, amount_gram="1000",
                          withdrawing=False, checked_at=badge["checked_at"])
    return card_text(badge, deal, counterparty_badge=bob, description=description), badge


def test_limit_constant():
    assert TELEGRAM_MESSAGE_LIMIT == 4096
    assert not set(PROTECTED_PREFIXES) & set(DROP_ORDER)


def test_worst_case_card_fits_and_keeps_protected_lines():
    card, badge = _worst_case("d" * 500)
    assert _tg_len(card) <= TELEGRAM_MESSAGE_LIMIT
    lines = card.splitlines()
    for prefix in PROTECTED_PREFIXES:
        assert sum(ln.startswith(prefix) for ln in lines) == 1, prefix
    assert "Key: " + badge["agent"] in lines
    assert lines[-1] == shortened_notice(badge["agent"])
    assert "Latest deal note:" not in card  # the least important line went first


def test_shortened_card_has_only_whole_lines():
    card, _ = _worst_case("d" * 500)
    known = ("AGENT CARD", "Key:", "Registration:", "Badge level:", "Stake:", "Deals:", "Latest deal ", "Disputes:",
             "Telegram check:", "Checked:", "Card shortened")
    assert all(ln.startswith(known) for ln in card.splitlines())
    assert all(ln.endswith("]") or ln.startswith(("AGENT CARD", "Key:", "Card shortened")) for ln in card.splitlines())


def test_drop_order_is_fixed_and_stops_when_it_fits():
    lines = ["AGENT CARD x", "Key: k", "Registration: r", "Stake: s", "Telegram check: t",
             "Latest deal note: " + "a" * 600, "Latest deal description: " + "b" * 600, "Checked: c"]
    key = "0" * 64
    notice = shortened_notice(key)
    base = len("\n".join(lines[:5] + ["Checked: c", notice]))
    out = fit_card(lines, key, limit=base).splitlines()
    assert out[-1] == notice and not any(ln.startswith("Latest deal") for ln in out) and "Checked: c" in out
    out = fit_card(lines, key, limit=base - 1).splitlines()  # Checked goes only after both deal lines
    assert "Checked: c" not in out and out[-1] == notice
    mid = len("\n".join(lines[:5] + ["Latest deal description: " + "b" * 600, "Checked: c", notice]))
    out = fit_card(lines, key, limit=mid).splitlines()
    assert any(ln.startswith("Latest deal description") for ln in out)
    assert not any(ln.startswith("Latest deal note") for ln in out)


def test_special_characters_in_description_are_plain_and_unescaped():
    description = SPECIAL
    card, _ = _worst_case(description, note="short")
    assert "Latest deal description: " + description + " [source: description supplied off-ledger" in card
    assert "\\_" not in card and "\\*" not in card  # no markup escaping: the message is plain text
    # Same text through the bot path: still plain text, and it is the only thing sent
    payload = bot.send_message_payload(1, card)
    assert payload == {"chat_id": 1, "text": card}


def test_no_parse_mode_is_passed(monkeypatch):
    badge, bob, deal = _demo()
    deal.pop("description")
    sent = []

    class Stop(Exception):
        pass

    calls = []

    def fake_get(url, timeout=30.0):
        if "getUpdates" in url:
            if calls:
                raise Stop
            calls.append(1)
            return dict(result=[dict(update_id=1, message=dict(chat=dict(id=7), text="/card " + badge["agent"]))])
        if "/deals" in url:
            return dict(deals=[deal])
        return bob if bob["agent"] in url else badge

    def fake_post(url, payload, timeout=30.0):
        sent.append((url, payload))
        return dict()

    monkeypatch.setattr(bot, "_get_json", fake_get)
    monkeypatch.setattr(bot, "_post_json", fake_post)
    with pytest.raises(Stop):
        bot.run("TOKEN", "http://issuer.invalid")
    assert len(sent) == 1 and sent[0][0].endswith("/sendMessage")
    assert set(sent[0][1]) == {"chat_id", "text"} and "parse_mode" not in sent[0][1]
    assert _tg_len(sent[0][1]["text"]) <= TELEGRAM_MESSAGE_LIMIT


def test_normal_cards_are_byte_identical_to_before():
    badge, bob, deal = _demo()
    description = deal.pop("description")
    cases = dict(alice_deal=card_text(badge, deal, counterparty_badge=bob, description=description),
                 alice_nodeal=card_text(badge))
    for path in (ROOT / "erc8004").glob("badge-*.json"):
        cases["erc_" + path.stem[len("badge-"):]] = card_text(json.loads(path.read_text()))
    assert len(cases) == 4
    for name, text in cases.items():
        assert text.encode("utf-8") == (GOLDEN / ("card_" + name + ".txt")).read_bytes(), name
        assert "Card shortened" not in text
