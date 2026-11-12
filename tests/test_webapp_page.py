"""The holder Mini App page in a real browser (Chromium through Playwright) against a live service.

Telegram's script is replaced by a stub that supplies init data signed by the stand-in key, the way
Telegram supplies it to a Mini App. Everything else is the shipped page. Skipped when Playwright or
Node is not installed. Set TGTRUST_SHOTS=<dir> to save screenshots of each state."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

from tgtrust import Credential, verify_credential  # noqa: E402
from tgtrust.client import AgentIdentity, CredentialFile, TgTrustClient, b64url_decode  # noqa: E402

from .test_webapp_flow import ANN, BEN, Live  # noqa: E402

SHOTS = os.environ.get("TGTRUST_SHOTS")
PHONE = {"width": 390, "height": 844}


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            chromium = p.chromium.launch()
        except Exception as exc:  # browser binary not installed
            pytest.skip(f"Chromium is not available: {exc}")
        yield chromium
        chromium.close()


@pytest.fixture
def live(issuer_key, telegram):
    app = Live(issuer_key, telegram)
    yield app
    app.close()


class Page:
    """One browser context = one device. `open` loads the page with the given Telegram state."""

    def __init__(self, browser, live, *, scheme="light", viewport=PHONE):
        self.live = live
        self.context = browser.new_context(viewport=viewport, color_scheme=scheme, device_scale_factor=2)
        self.context.grant_permissions(["clipboard-read", "clipboard-write"])
        self.page = self.context.new_page()
        self.problems: list[str] = []
        self.foreign: list[str] = []
        self.page.on("console", lambda m: self.problems.append(m.text) if m.type == "error" else None)
        self.page.on("pageerror", lambda e: self.problems.append(str(e)))
        self.page.on("request", self._seen)
        self.init_data = ""
        self.language = "en"
        self.page.route("https://telegram.org/js/telegram-web-app.js", self._telegram)

    def _seen(self, request) -> None:
        if not request.url.startswith(self.live.origin) and "telegram.org/js/telegram-web-app.js" not in request.url:
            self.foreign.append(request.url)

    def _telegram(self, route) -> None:
        stub = ("window.Telegram={WebApp:{initData:%s,initDataUnsafe:{user:{language_code:%s}},"
                "ready(){},expand(){},HapticFeedback:{notificationOccurred(){}}}};"
                % (json.dumps(self.init_data), json.dumps(self.language)))
        route.fulfill(content_type="text/javascript", body=stub)

    def open(self, user=None, *, language="en"):
        self.init_data = self.live.init_data(user) if user else ""
        self.language = language
        self.page.goto(self.live.origin + "/app/")
        self.page.wait_for_selector("#check-issuer:not(.pending)")
        return self.page

    def shot(self, name: str) -> None:
        if SHOTS:
            Path(SHOTS).mkdir(parents=True, exist_ok=True)
            self.page.screenshot(path=str(Path(SHOTS) / f"{name}.png"), full_page=True)

    def no_overflow(self) -> bool:
        return self.page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")

    def close(self) -> None:
        self.context.close()


@pytest.fixture
def device(browser, live):
    d = Page(browser, live)
    yield d
    d.close()


def result_file(page) -> dict:
    page.wait_for_selector("#result:not([hidden])")
    return json.loads(page.input_value("#result-file"))


def test_own_key_flow_in_the_browser(device, live):
    agent = AgentIdentity.generate()
    page = device.open(ANN)
    assert page.inner_text("#check-tg") == "yes" and len(page.inner_text("#check-issuer")) == 16
    device.shot("1-start-light")
    page.fill("#agent-key", agent.hex)
    page.click("#go")
    package = result_file(page)
    device.shot("2-credential-ready")
    assert package["format"] == "tgtrust-credential/v1" and package["agent_public_key"] == agent.hex
    assert "agent_private_key" not in json.dumps(package)
    # the agent-side loader accepts the page's file as is, and it points at this issuer
    loaded = CredentialFile.from_dict(package)
    assert loaded.issuer == live.origin + "/v1" and loaded.agent_public_key == agent.public_key
    credential = Credential(b64url_decode(package["token"]), b64url_decode(package["signature"]))
    assert verify_credential(live.issuer.public_key, credential)
    assert TgTrustClient(live.base).register(agent, credential, b64url_decode(package["salt"]))["agent"] == agent.hex
    # the copy button puts exactly the file on the clipboard
    page.click("#copy")
    page.wait_for_selector('#status:text-is("Copied.")')
    assert json.loads(page.evaluate("navigator.clipboard.readText()")) == package
    assert page.is_hidden("#result-warning") and page.is_hidden("#go")
    assert device.problems == [] and device.foreign == [] and device.no_overflow()


def test_new_key_flow_registers_and_forgets(device, live):
    page = device.open(ANN)
    page.check('input[name="mode"][value="new"]')
    assert page.is_hidden("#own-fields")
    page.click("#go")
    agent_file = result_file(page)
    device.shot("3-agent-registered")
    assert agent_file["format"] == "tgtrust-agent/v1" and page.is_visible("#result-warning")
    agent = AgentIdentity.from_bytes(bytes.fromhex(agent_file["agent_private_key"]))
    assert CredentialFile.from_dict(agent_file["credential"]).agent_public_key == agent.public_key
    assert agent.hex == agent_file["agent_public_key"] == agent_file["credential"]["agent_public_key"]
    assert TgTrustClient(live.base).badge(agent.hex)["unique_owner"] is True
    # the saved copy survives a reload until the holder says it is saved, then it is gone
    page = device.open(ANN)
    assert result_file(page) == agent_file
    page.click("#forget")
    assert page.evaluate("localStorage.length") == 0
    assert page.is_hidden("#result") and page.is_visible("#choose")
    assert page.input_value("#result-file") == ""
    assert device.problems == [] and device.foreign == []


def test_lost_answer_is_finished_after_reopening(device, live):
    agent = AgentIdentity.generate()
    page = device.open(ANN)

    def lose(route):
        route.fetch()  # the issuer serves the request and records the account
        route.abort()  # the answer never reaches the page

    page.route("**/v1/issue", lose)
    page.fill("#agent-key", agent.hex)
    page.click("#go")
    page.wait_for_selector("#status.error")
    assert "nothing is lost" in page.inner_text("#status")
    page.unroute("**/v1/issue")
    # the holder closes and reopens the Mini App: fresh Telegram data, same saved request
    page = device.open(ANN)
    assert page.is_visible("#resume") and agent.hex in page.inner_text("#resume-agent")
    assert page.is_hidden("#choose") and page.inner_text("#go") == "Finish the request"
    device.shot("4-unfinished-request")
    page.click("#go")
    package = result_file(page)
    credential = Credential(b64url_decode(package["token"]), b64url_decode(package["signature"]))
    assert package["agent_public_key"] == agent.hex and verify_credential(live.issuer.public_key, credential)
    assert device.foreign == []


def test_second_credential_message(browser, live):
    first = Page(browser, live)
    page = first.open(ANN)
    page.fill("#agent-key", AgentIdentity.generate().hex)
    page.click("#go")
    result_file(page)
    first.close()
    second = Page(browser, live)  # another device of the same account: nothing saved there
    page = second.open(ANN)
    page.fill("#agent-key", AgentIdentity.generate().hex)
    page.click("#go")
    page.wait_for_selector("#status.error")
    assert "already received" in page.inner_text("#status")
    # the refused request is kept, so the page offers to finish it, not to start a third one
    assert page.is_visible("#resume")
    second.close()


def test_outside_telegram_nothing_can_be_sent(device):
    page = device.open(None)
    assert page.inner_text("#check-tg") == "no"
    assert page.is_disabled("#go")
    assert "Mini App" in page.inner_text("#status")
    device.shot("5-outside-telegram")
    assert device.foreign == []


def test_bad_public_key_is_caught_before_anything_is_sent(device, live):
    page = device.open(ANN)
    sent = []
    page.on("request", lambda r: sent.append(r.url) if r.method == "POST" else None)
    page.fill("#agent-key", "not-a-key")
    page.click("#go")
    page.wait_for_selector("#status.error")
    assert "64 hex" in page.inner_text("#status") and sent == []
    assert page.evaluate("localStorage.length") == 0
    # a correct key afterwards works: the account was not used up
    page.fill("#agent-key", AgentIdentity.generate().hex)
    page.click("#go")
    result_file(page)


def test_stale_saved_request_can_only_be_removed(device, live):
    page = device.open(ANN)
    page.evaluate("""localStorage.setItem('tgtrust.holder.pending.v1', JSON.stringify({v:1, key_id:'0000000000000000',
        epoch:'v0', mode:'own', agent:'ab'.repeat(32), seed:null, salt:'AA', token:'AA', blinded:'AA', inverse:'2',
        signature:null, registered:false, created_at:1}))""")
    page = device.open(ANN)
    assert page.is_visible("#stale") and page.is_hidden("#go") and page.is_hidden("#resume")
    page.click("#discard")
    assert page.is_visible("#choose") and page.is_visible("#go")
    assert page.evaluate("localStorage.length") == 0


@pytest.mark.parametrize("width", [320, 360, 390, 768])
def test_russian_dark_theme_fits_every_width(browser, live, width):
    d = Page(browser, live, scheme="dark", viewport={"width": width, "height": 800})
    page = d.open(BEN, language="ru")
    assert page.inner_text("h1") == "Удостоверение агента" and page.inner_text("#check-tg") == "да"
    assert page.get_attribute("html", "lang") == "ru"
    assert d.no_overflow()
    page.check('input[name="mode"][value="new"]')
    page.click("#go")
    result_file(page)
    assert page.inner_text("#result-title") == "Агент зарегистрирован"
    assert d.no_overflow() and d.problems == []
    if width == 390:
        d.shot("6-russian-dark")
    d.close()


def test_page_has_no_inline_code_and_a_strict_policy():
    from tgtrust.service import WEBAPP_DIR

    html = (WEBAPP_DIR / "holder.html").read_text()
    assert "default-src 'none'" in html and "connect-src 'self'" in html and "unsafe-inline" not in html
    assert html.count("<script") == 2 and "onclick" not in html and "style=" not in html
    for name in ("holder.js", "holder-core.js", "blindrsa.js"):
        code = (WEBAPP_DIR / name).read_text()
        for banned in ("eval(", "innerHTML", "document.write", "XMLHttpRequest", "sessionStorage", "document.cookie"):
            assert banned not in code, (name, banned)
    core = (WEBAPP_DIR / "holder-core.js").read_text() + (WEBAPP_DIR / "blindrsa.js").read_text()
    assert "localStorage" not in core and "document." not in core  # the flow code is page-free
