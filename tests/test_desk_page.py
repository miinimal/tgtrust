"""Trust Desk's page in a real browser (Chromium through Playwright): samples, states, live-lookup consent, layout
on a phone and a desktop in light and dark, and no console errors. Outside hosts are stubbed: no test touches the
network. Set TGTRUST_SHOTS=<dir> to save screenshots."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

from .desk_server import NODE, ROOT, serve  # noqa: E402

pytestmark = pytest.mark.skipif(NODE is None, reason="Node is not installed")
SHOTS = os.environ.get("TGTRUST_SHOTS")
DESK = ROOT / "desk"
ISSUER = "https://minimal.tailee59dc.ts.net"
CONCORDIUM = "https://agent-registry-mcp.concordium.com"
DEMO_KEY = "dbc55639df6bfeef7366bd3c0436d0b75842ff63c3701625d818cbb7022aee26"
GOLDEN = ROOT / "tests" / "golden" / "concordium"


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            chromium = p.chromium.launch()
        except Exception as exc:  # browser binary not installed
            pytest.skip(f"Chromium is not available: {exc}")
        yield chromium
        chromium.close()


@pytest.fixture(scope="module")
def site():
    with serve(DESK) as url:
        yield url


class Outside:
    """Answers for the two live-lookup origins, and a record of every outside request."""

    def __init__(self, issuer_up: bool):
        self.issuer_up = issuer_up
        self.requests: list[dict] = []

    def handle(self, route):
        req = route.request
        self.requests.append({"url": req.url, "method": req.method, "headers": req.headers})
        if req.url.startswith(ISSUER):
            if not self.issuer_up:
                return route.abort("connectionrefused")
            badge = {"agent": DEMO_KEY, "level": "verified", "unique_owner": True, "issuer_key_id": "9fc6ef5575f072ab",
                     "registered_at": 1794602157,
                     "stake": {"network": "testnet", "contract": "kQD0dNGo6GJnxq7Dc5HWcEfoBWI8UkUwZ6-w7gpwm8G11z-w",
                               "found": False, "amount_nanogram": 0, "withdrawing": False},
                     "history": {"deals": {"count": 2, "with_staked_counterparty": 1},
                                 "disputes": {"filed_against": 0, "upheld_against": 0}}}
            return route.fulfill(status=200, body=json.dumps(badge), content_type="application/json",
                                 headers={"Access-Control-Allow-Origin": "*"})
        if req.url.startswith(CONCORDIUM):
            cors = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Methods": "*"}
            if req.method == "OPTIONS":
                return route.fulfill(status=200, headers=cors)
            null = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "null"}],
                                                          "isError": False}}
            return route.fulfill(status=200, body=json.dumps(null), content_type="application/json", headers=cors)
        return route.abort("blockedbyclient")


def open_desk(browser, site, *, phone=False, dark=False, issuer_up=False):
    opts = {"viewport": {"width": 390, "height": 844}, "is_mobile": True, "has_touch": True,
            "device_scale_factor": 1} if phone else {"viewport": {"width": 1280, "height": 900}}
    ctx = browser.new_context(color_scheme="dark" if dark else "light", **opts)
    outside = Outside(issuer_up)
    ctx.route(lambda url: not url.startswith(site), outside.handle)
    page = ctx.new_page()
    errors: list[str] = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(site)
    page.wait_for_selector("html[data-desk-ready=true]")
    return ctx, page, outside, errors


def run_sample(page, name: str) -> str:
    page.evaluate("document.querySelector('#result-meta').textContent = ''")
    page.click(f"[data-sample={name}]")
    page.locator("#result-meta", has_text="Checked").wait_for()
    page.locator("#check-button", has_text="Check agent").wait_for()
    return page.text_content("#result-state")


def check_text(page, check: str) -> str:
    return page.inner_text(f"#result-checks [data-check={check}]")


def shot(page, name: str):
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(SHOTS) / f"desk-{name}.png"), full_page=True)


@pytest.mark.parametrize("phone", [False, True], ids=["desktop", "phone"])
@pytest.mark.parametrize("dark", [False, True], ids=["light", "dark"])
def test_samples_states_and_layout(browser, site, phone, dark):
    ctx, page, outside, errors = open_desk(browser, site, phone=phone, dark=dark)
    try:
        assert run_sample(page, "concordium") == "Partial"
        assert "a card is only a claim" in check_text(page, "card")
        assert page.text_content("#tier-now") == "anonymous"
        assert run_sample(page, "fresh") == "Partial"
        assert "the key signed the desk's challenge" in check_text(page, "proof")
        assert run_sample(page, "forged") == "Invalid"
        assert "the issuer's signature does not verify" in check_text(page, "credential")
        # Nothing ran off the side of the screen, and nothing left the page.
        assert page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth") == 0
        for selector in ("#result", ".input-panel", "#assistant", ".top"):
            box = page.locator(selector).first.bounding_box()
            assert box["x"] >= 0 and box["x"] + box["width"] <= page.viewport_size["width"] + 0.5, selector
        assert outside.requests == []
        assert errors == []
        shot(page, f"{'phone' if phone else 'desktop'}-{'dark' if dark else 'light'}")
    finally:
        ctx.close()


def test_live_lookups_are_off_until_allowed_and_name_their_origins(browser, site):
    ctx, page, outside, errors = open_desk(browser, site)
    try:
        origins = page.inner_text("#live-origins")
        assert ISSUER in origins and CONCORDIUM in origins
        run_sample(page, "concordium")
        assert outside.requests == []
        assert "live lookups are off" in check_text(page, "registration")
        page.click("#live-toggle")
        page.locator("#result-meta", has_text="live lookups on").wait_for()
        hosts = {r["url"].split("/")[2] for r in outside.requests}
        assert hosts <= {"minimal.tailee59dc.ts.net", "agent-registry-mcp.concordium.com"}
        assert all("authorization" not in r["headers"] and "cookie" not in r["headers"] for r in outside.requests)
        assert "live lookup unavailable: the result uses signed data only" in check_text(page, "registration")
        assert page.get_attribute("#live-toggle", "aria-pressed") == "true"
        assert errors == [] or all("ERR_CONNECTION_REFUSED" in e or "Failed to load" in e for e in errors)
    finally:
        ctx.close()


def test_live_badge_shows_wording_and_network_label(browser, site):
    ctx, page, outside, _ = open_desk(browser, site, issuer_up=True)
    try:
        page.click("#live-toggle")
        page.fill("#f-key", DEMO_KEY)
        page.click("#check-button")
        page.locator("#result-checks [data-check=deals]").wait_for()
        assert "level verified: registered with one Telegram account per issuer epoch (issuer-attested), owner not " \
               "disclosed" in check_text(page, "registration")
        assert "no active stake on TON testnet" in check_text(page, "stake")
        assert "2 co-signed deal records (1 with staked counterparties)" in check_text(page, "deals")
        assert page.text_content("#tier-proven") == "verified"
        body = page.inner_text("body").lower()
        for forbidden in ("unique person", "real human", "kyc", "completed jobs", "successful deals"):
            assert forbidden not in body
    finally:
        ctx.close()


def test_bad_input_is_explained_in_the_form(browser, site):
    ctx, page, _, errors = open_desk(browser, site, phone=True)
    try:
        page.fill("#f-key", "{ not json")
        page.click("#check-button")
        assert page.text_content("#form-error") == "The agent card is not valid JSON"
        page.fill("#f-key", "1234")
        page.click("#check-button")
        assert "64 hexadecimal characters" in page.text_content("#form-error")
        assert page.is_hidden("#result")
        assert errors == []
    finally:
        ctx.close()
