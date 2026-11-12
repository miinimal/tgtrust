"""Trust badge: one object that tells a bot what it can rely on about an agent.

Three facts, from three independent sources, none of which reveals the owner:
- registration: the registry (blocks 1-4) — the Telegram check (see TELEGRAM_CHECK_SCOPE);
- stake: the StakeRegistry contract on TON (block 5) — Gram that burns on a dispute verdict;
- history: registration age and the confirmed-deals ledger (block 7).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from .deals import DealStats
from .disputes import DisputeStats
from .registry import AgentRecord
from .stake import StakeInfo

LEVEL_UNKNOWN = "unknown"     # never registered
LEVEL_REVOKED = "revoked"     # registration revoked
LEVEL_VERIFIED = "verified"   # registered, no active stake
LEVEL_STAKED = "staked"       # registered and an active stake
LEVEL_NAMES = (LEVEL_UNKNOWN, LEVEL_REVOKED, LEVEL_VERIFIED, LEVEL_STAKED)

# One source of truth for the wording of the Telegram check. The card, the bot help text, the ERC-8004 export
# documentation and the examples take their human-readable text from here. The legacy JSON key `unique_owner`
# (badge and registry record) means exactly this and nothing more; see docs/ERC8004_EXPORT.md.
TELEGRAM_CHECK_LABEL = "Telegram check"
TELEGRAM_CHECK_SCOPE = "issuer credential, one Telegram account per issuer epoch"
TELEGRAM_CHECK_NOT_CHECKED = "Owner identity is not checked and not revealed."
TELEGRAM_CHECK_MEANING = f"{TELEGRAM_CHECK_SCOPE}. {TELEGRAM_CHECK_NOT_CHECKED}"
TELEGRAM_CHECK_LINE = f"{TELEGRAM_CHECK_LABEL}: {TELEGRAM_CHECK_MEANING}"
ISSUER_CREDENTIAL_PREFIX = "Issuer credential: "

# Prefix of the stake lines (short badge text and card).
STAKE_PREFIX = "Stake: "


@dataclass(frozen=True)
class StakeSource:
    network: str
    contract: str


def trust_level(record: AgentRecord | None, stake: StakeInfo | None) -> str:
    if record is None:
        return LEVEL_UNKNOWN
    if record.revoked:
        return LEVEL_REVOKED
    if stake is not None and stake.found and stake.amount > 0 and not stake.withdrawing:
        return LEVEL_STAKED
    return LEVEL_VERIFIED


def build_badge(
    agent_public_key_hex: str,
    record: AgentRecord | None,
    stake: StakeInfo | None,
    *,
    stake_source: StakeSource | None,
    stake_error: str | None = None,
    deals: DealStats | None = None,
    disputes: DisputeStats | None = None,
    now: int,
) -> dict:
    """Composes the badge. `stake` is None when no stake source is configured or the lookup failed."""
    if stake_source is None:
        stake = None  # a stake nobody can check does not count
    badge: dict = {
        "agent": agent_public_key_hex.lower(),
        "level": trust_level(record, stake),
        "unique_owner": bool(record and not record.revoked),
        "issuer_key_id": record.issuer_key_id if record else None,
        "registered_at": record.registered_at if record else None,
    }
    if stake_source is None:
        badge["stake"] = None
    elif stake is None:
        badge["stake"] = {
            "network": stake_source.network,
            "contract": stake_source.contract,
            "found": None,
            "error": stake_error or "lookup_failed",
        }
    else:
        badge["stake"] = stake.to_dict(stake_source.network, stake_source.contract)
    badge["history"] = {
        "registered_at": record.registered_at if record else None,
        "days_registered": max(0, (now - record.registered_at) // 86400) if record else 0,
        "deals": deals.to_dict() if deals else None,
        "disputes": disputes.to_dict() if disputes else None,
    }
    badge["checked_at"] = now
    return badge


def badge_text(badge: dict) -> str:
    """Plain-text rendering for chat bots."""
    level = badge["level"]
    lines = [f"Agent {badge['agent'][:16]}…", f"Level: {level}"]
    lines.append(ISSUER_CREDENTIAL_PREFIX + ("yes" if badge["unique_owner"] else "no"))
    stake = badge.get("stake")
    if stake is None:
        lines.append(STAKE_PREFIX + "not checked")
    elif stake.get("found") is None:
        lines.append(STAKE_PREFIX + "lookup failed")
    elif not stake["found"]:
        lines.append(STAKE_PREFIX + "none")
    else:
        state = " (withdrawing)" if stake["withdrawing"] else ""
        lines.append(f"{STAKE_PREFIX}{stake['amount_gram']} GRAM{state} on {stake['network']}")
    days = badge["history"]["days_registered"]
    if badge["registered_at"]:
        lines.append(f"Registered: {days} day(s) ago")
    deals = badge["history"].get("deals")
    if deals:
        lines.append(f"Deals: {deals['count']} ({deals['with_staked_counterparty']} with staked counterparties, "
                     f"{deals['distinct_counterparties']} distinct)")
    disputes = badge["history"].get("disputes")
    if disputes and disputes["filed_against"]:
        lines.append(f"Disputes against: {disputes['filed_against']} ({disputes['upheld_against']} upheld, "
                     f"{disputes['open_against']} open)")
    return "\n".join(lines)


UNKNOWN = "unknown"  # a value that could not be read; never the same thing as zero

TELEGRAM_CHECK_LIMITS = TELEGRAM_CHECK_LINE  # old name, kept for importers


TELEGRAM_MESSAGE_LIMIT = 4096  # Telegram cuts a message longer than this (counted in UTF-16 code units to be safe)
MAX_VALUE_CHARS = 120          # cap for a free-form value inside a protected line (key id, network, contract, error)

# The card is sent as PLAIN TEXT (tgtrust/bot.py passes no parse_mode), so nothing in it is interpreted as
# markup and no escaping is needed or applied: `_ * [ ] < &` etc. are shown literally.

# Lines that are never dropped (matched by line prefix): the key, the registration line, the stake line and
# the Telegram-check line (both of its variants). The header line is not in the drop order either.
PROTECTED_PREFIXES = ("Key:", "Registration:", "Stake:", "Telegram check:")

# Shortening order when the card is over the limit: whole lines are dropped, least important first, until the
# card plus the one-line notice fits. A line is never cut in the middle.
DROP_ORDER = (
    "Latest deal note:",
    "Latest deal description:",
    "Latest deal signatures:",
    "Latest deal counterparty:",
    "Latest deal id:",
    "Checked:",
    "Disputes:",
    "Deals:",
    "Badge level:",
)


def _tg_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _clip(value, limit: int = MAX_VALUE_CHARS) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def shortened_notice(key: str) -> str:
    return (f"Card shortened to fit one Telegram message. Full record: badge endpoint /agents/{key}/badge "
            f"and ledger /agents/{key}/deals on the issuer service.")


def fit_card(lines: list[str], key: str, limit: int = TELEGRAM_MESSAGE_LIMIT) -> str:
    """Joins the card lines; if over `limit`, drops whole lines in DROP_ORDER and appends one notice line."""
    text = "\n".join(lines)
    if _tg_len(text) <= limit:
        return text
    notice = shortened_notice(key)
    kept = list(lines)
    for prefix in DROP_ORDER:
        if _tg_len("\n".join(kept + [notice])) <= limit:
            break
        kept = [ln for ln in kept if not ln.startswith(prefix)]
    return "\n".join(kept + [notice])


def _utc(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _latest_deal_lines(key: str, deal: dict | None, cp_badge: dict | None, description: str | None) -> list[str]:
    src = "[source: ledger]"
    if not deal:
        return [f"Latest deal id: {UNKNOWN}, the deal record was not read {src}",
                f"Latest deal description: {UNKNOWN}, the deal record was not read {src}",
                f"Latest deal counterparty: {UNKNOWN}, the deal record was not read {src}",
                f"Latest deal signatures: {UNKNOWN}, the deal record was not read {src}"]
    lines = [f"Latest deal id: {deal.get('deal_id') or UNKNOWN} {src}"]
    memo = deal.get("memo_hash")
    if description and memo and hashlib.sha256(description.encode()).hexdigest() == memo:
        lines.append(f"Latest deal description: {description} [source: description supplied off-ledger; "
                     f"its SHA-256 equals memo_hash {memo[:16]}… recorded in the ledger]")
    else:
        lines.append(f"Latest deal description: {UNKNOWN}, the ledger keeps only memo_hash "
                     f"{(memo or UNKNOWN)[:16]}…, no matching text was read {src}")
    parties = deal.get("parties") or []
    others = [p for p in parties if p != key]
    if len(parties) == 2 and len(others) == 1:
        cp = others[0]
        level = (cp_badge or {}).get("level") if (cp_badge or {}).get("agent") == cp else None
        lines.append(f"Latest deal counterparty: {cp[:8]}…{cp[-4:]} [source: ledger]; badge level "
                     f"{level or UNKNOWN} [source: counterparty badge endpoint]")
    else:
        lines.append(f"Latest deal counterparty: {UNKNOWN}, this agent is not one of the two parties in the record {src}")
    if len(parties) == 2:
        lines.append("Latest deal signatures: the ledger accepts a deal only after verifying the signatures of "
                     "both parties, and recorded this one (signatures themselves are not stored) [source: ledger]")
    else:
        lines.append(f"Latest deal signatures: {UNKNOWN}, the record does not list two parties {src}")
    if deal.get("note"):
        lines.append(f"Latest deal note: {deal['note']} [source: example capture file]")
    return lines


def card_text(badge: dict, deal: dict | None = None, *, counterparty_badge: dict | None = None,
              description: str | None = None) -> str:
    """Readable agent card built from the same record as the badge.

    Every statement names its source: badge endpoint, ledger, or TON stake read (with read time).
    0 confirmed deals (ledger read, nothing there) and «unknown» (could not be read) are distinct.

    `deal` is the ledger record of the latest confirmed deal (item of `GET /agents/{key}/deals`); it is
    used only when the badge reports at least one deal. `counterparty_badge` is the badge of the other
    party. `description` is the work description supplied off-ledger: the ledger keeps only `memo_hash`,
    so the text is shown only if its SHA-256 equals that hash, otherwise it is «unknown».
    """
    key = badge["agent"]
    lines = [f"AGENT CARD {key[:8]}…{key[-4:]}", f"Key: {key}"]

    # --- registration: badge endpoint
    if badge.get("registered_at"):
        lines.append(f"Registration: registered {_utc(badge['registered_at'])}, "
                     f"issuer key {_clip(badge.get('issuer_key_id') or UNKNOWN)}"
                     f"{' (REVOKED)' if badge['level'] == LEVEL_REVOKED else ''} [source: badge endpoint]")
    else:
        lines.append("Registration: not registered, no credential on record [source: badge endpoint]")
    lines.append(f"Badge level: {'not registered (level unknown)' if badge['level'] == LEVEL_UNKNOWN else badge['level']}"
                 " [source: badge endpoint]")

    # --- stake: TON stake read
    stake = badge.get("stake")
    if stake is None:
        lines.append(STAKE_PREFIX + "unknown, no TON stake source configured, nothing was read [source: TON stake read, not performed]")
    else:
        net = f"TON {_clip(stake['network'])}"
        when = f", read {_utc(stake['checked_at'])}" if stake.get("checked_at") else ""
        src = f"[source: {net} stake read{when}; contract {_clip(stake['contract'])}]"
        if stake.get("found") is None:
            lines.append(f"{STAKE_PREFIX}unknown, the read failed ({_clip(stake.get('error') or 'lookup_failed')}) {src}")
        elif not stake["found"]:
            lines.append(f"{STAKE_PREFIX}none on {net} {src}")
        else:
            state = ", withdrawing" if stake.get("withdrawing") else ""
            lines.append(f"{STAKE_PREFIX}{stake['amount_gram']} GRAM on {net}{state} {src}")

    # --- history: ledger
    history = badge.get("history") or {}
    deals = history.get("deals")
    if deals is None:
        lines.append("Deals: unknown, ledger value was not available [source: ledger]")
    elif deals["count"] == 0:
        lines.append("Deals: 0 confirmed deals [source: ledger]")
    else:
        lines.append(f"Deals: {deals['count']} confirmed deals, {deals['with_staked_counterparty']} with staked "
                     f"counterparties, {deals['distinct_counterparties']} distinct counterparties [source: ledger]")
    if deals and deals["count"] > 0:
        lines.extend(_latest_deal_lines(key, deal, counterparty_badge, description))
    disputes = history.get("disputes")
    if disputes is None:
        lines.append("Disputes: unknown, ledger value was not available [source: ledger]")
    else:
        lines.append(f"Disputes: {disputes['filed_against']} filed against ({disputes['upheld_against']} upheld, "
                     f"{disputes['open_against']} open), {disputes['filed_by']} filed by this agent [source: ledger]")

    if badge.get("registered_at"):
        lines.append(TELEGRAM_CHECK_LIMITS + " [source: badge endpoint]")
    else:
        lines.append(f"{TELEGRAM_CHECK_LABEL}: not performed (agent is not registered). [source: badge endpoint]")
    lines.append(f"Checked: {_utc(badge['checked_at'])} [source: badge endpoint]")
    return fit_card(lines, key)
