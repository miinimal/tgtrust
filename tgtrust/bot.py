"""Demo Telegram bot: answers `/badge <agent key hex>` with the trust badge and `/card` with the agent card.

Standard library only (long polling over the Bot API). Run:

    TGTRUST_BOT_TOKEN=... TGTRUST_BADGE_URL=https://issuer.example/v1 python -m tgtrust.bot

`TGTRUST_BADGE_URL` is the issuer service base (the bot calls `/agents/{key}/badge`).
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from .badge import LEVEL_NAMES, TELEGRAM_CHECK_LINE, badge_text, card_text

HELP = (
    "Send /badge <agent key> (64 hex characters) for a short badge, or /card <agent key> for a full card:\n"
    f"{TELEGRAM_CHECK_LINE}\n"
    "Also: Gram stake on TON testnet, deals history.\n"
    f"Levels: {', '.join(LEVEL_NAMES)}."
)


def parse_command(text: str) -> tuple[str, str] | None:
    """Returns (command, argument) for '/cmd arg' messages, ignoring the @botname suffix."""
    if not text or not text.startswith("/"):
        return None
    parts = text.split(maxsplit=1)
    command = parts[0].split("@", 1)[0].lower()
    return command, (parts[1].strip() if len(parts) > 1 else "")


def reply_for(text: str, fetch_badge, fetch_deals=None) -> str:
    parsed = parse_command(text)
    if parsed is None:
        return HELP
    command, arg = parsed
    if command in ("/start", "/help"):
        return HELP
    if command in ("/badge", "/card"):
        key = arg.lower()
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            return "The agent key must be 64 hex characters."
        try:
            badge = fetch_badge(key)
        except Exception as exc:  # noqa: BLE001 - the user needs a message, not a trace
            return f"Could not fetch the badge: {exc}"
        if command == "/badge":
            return badge_text(badge)
        return _card_reply(key, badge, fetch_badge, fetch_deals)
    return HELP


def _card_reply(key: str, badge: dict, fetch_badge, fetch_deals) -> str:
    """Card with the latest confirmed deal read through the ledger read path; anything unread stays unknown."""
    deals = (badge.get("history") or {}).get("deals")
    if not deals or not deals.get("count") or fetch_deals is None:
        return card_text(badge)
    try:
        deal = (fetch_deals(key).get("deals") or [None])[0]
    except Exception:  # noqa: BLE001 - an unread deal record is shown as unknown
        return card_text(badge)
    cp_badge = None
    if deal:
        others = [p for p in deal.get("parties", []) if p != key]
        if len(others) == 1:
            try:
                cp_badge = fetch_badge(others[0])
            except Exception:  # noqa: BLE001
                cp_badge = None
    return card_text(badge, deal, counterparty_badge=cp_badge)


def _get_json(url: str, timeout: float = 30.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "tgtrust-bot/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _post_json(url: str, payload: dict, timeout: float = 30.0) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def send_message_payload(chat_id, text: str) -> dict:
    """Body of the Bot API sendMessage call. PLAIN TEXT on purpose: no `parse_mode` is ever set, so Telegram does
    not interpret `_ * [ ] < &` and the like, and dynamic values need no escaping. A test pins this."""
    return {"chat_id": chat_id, "text": text}


NETWORK_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError, TimeoutError, ValueError)
RETRY_PAUSE_SECONDS = 5


def _token_of(api: str) -> str:
    return api.rsplit("/bot", 1)[-1] if "/bot" in api else ""


def _log(message: str, token: str) -> None:
    """One line to stderr; the bot token never leaves the process."""
    if token:
        message = message.replace(token, "***")
    print(" ".join(message.split()), file=sys.stderr)


def poll_once(
    api: str,
    offset: int,
    fetch_badge,
    fetch_deals=None,
    get_json=None,
    post_json=None,
    sleep=time.sleep,
    token: str | None = None,
) -> int:
    """One polling round: reads updates, answers each, returns the new offset.

    A failed getUpdates logs one line, pauses and returns the offset unchanged. A failed sendMessage logs one
    line and does not stop the rest of the batch; the offset moves past every update that was read."""
    # looked up at call time (None = module default) so the module functions stay patchable
    get_json = get_json or _get_json
    post_json = post_json or _post_json
    if token is None:
        token = _token_of(api)
    try:
        updates = get_json(f"{api}/getUpdates?timeout=50&offset={offset}", timeout=60)
    except NETWORK_ERRORS as exc:
        _log(f"getUpdates failed: {exc}", token)
        sleep(RETRY_PAUSE_SECONDS)
        return offset
    result = updates.get("result") if isinstance(updates, dict) else None
    if not isinstance(result, list):
        return offset
    for update in result:
        if not isinstance(update, dict):
            continue
        update_id = update.get("update_id")
        if isinstance(update_id, bool) or not isinstance(update_id, int):
            continue
        offset = max(offset, update_id + 1)
        message = update.get("message")
        if not isinstance(message, dict):
            continue
        chat = message.get("chat")
        text = message.get("text")
        if not isinstance(chat, dict) or chat.get("id") is None or not isinstance(text, str) or not text:
            continue
        try:
            post_json(f"{api}/sendMessage", send_message_payload(chat["id"], reply_for(text, fetch_badge, fetch_deals)))
        except NETWORK_ERRORS as exc:
            _log(f"sendMessage failed: {exc}", token)
    return offset


def run(token: str, badge_url: str, get_json=None, post_json=None, sleep=time.sleep) -> None:
    get_json = get_json or _get_json
    post_json = post_json or _post_json
    api = f"https://api.telegram.org/bot{token}"
    offset = 0

    def fetch_badge(key: str) -> dict:
        return get_json(f"{badge_url.rstrip('/')}/agents/{key}/badge")

    def fetch_deals(key: str) -> dict:
        return get_json(badge_url.rstrip("/") + "/agents/" + key + "/deals?limit=1")

    print("tgtrust badge bot: polling", file=sys.stderr)
    while True:
        offset = poll_once(api, offset, fetch_badge, fetch_deals, get_json, post_json, sleep, token)


if __name__ == "__main__":
    bot_token = os.environ.get("TGTRUST_BOT_TOKEN")
    base_url = os.environ.get("TGTRUST_BADGE_URL")
    if not bot_token or not base_url:
        print("set TGTRUST_BOT_TOKEN and TGTRUST_BADGE_URL", file=sys.stderr)
        sys.exit(2)
    run(bot_token, base_url)
