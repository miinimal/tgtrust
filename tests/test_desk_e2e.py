"""Spec section 6, end to end, in Chromium with two real origins and a scripted router.

Trust Desk (desk/) is served as http://127.0.0.1:<port>/ and the paid API operator desk (demo-api/, the caller) as
http://localhost:<port>/: two origins, as in the reference linking check. The demo's network is served with its
partner URL pointed at the local Trust Desk. A scripted router (tests/desk_router.py) stands in for the model; every
other host is blocked and recorded, so nothing leaves the machine. The fake key never names a real account.

Each test is one row of docs/COGNIZANT.md, section 6.
"""

from __future__ import annotations

import json
import shutil
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

from .desk_router import MockRouter  # noqa: E402
from .desk_server import NODE, ROOT, serve, serve_static  # noqa: E402

pytestmark = pytest.mark.skipif(NODE is None, reason="Node is not installed")
KEY = "sk-test-trustdesk-not-a-real-key-7f3a"
DESK = ROOT / "desk"
DEMO = ROOT / "demo-api"
PUBLIC_DESK = "https://miinimal.github.io/tgtrust/trust_desk"


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            chromium = p.chromium.launch()
        except Exception as exc:  # browser binary not installed
            pytest.skip(f"Chromium is not available: {exc}")
        yield chromium
        chromium.close()


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@contextmanager
def sites(tmp: Path, *, desk_patch=None, demo_patch=None, peer_url_name="trust_desk", extra_peer: Path | None = None):
    """Serve Trust Desk and the demo on two origins; yield (desk_url, demo_url, desk_log, demo_log, extra_url)."""
    desk_dir = tmp / "desk"
    shutil.copytree(DESK, desk_dir, ignore=shutil.ignore_patterns("tests", "tools"))
    if desk_patch:
        desk_patch(desk_dir)
    desk_log, demo_log = tmp / "desk.log", tmp / "demo.log"
    with serve(desk_dir, open_as="127.0.0.1", log=desk_log) as desk_url:
        extra_ctx = serve_static(extra_peer) if extra_peer else None
        extra_url = extra_ctx.__enter__() if extra_ctx else None
        try:
            demo_dir = tmp / "demo"
            shutil.copytree(DEMO, demo_dir)
            net_path, man_path = demo_dir / "paid_api_desk.network.json", demo_dir / "agent-manifest.json"
            net, man = _read(net_path), _read(man_path)
            peer = f"{desk_url}{peer_url_name}"
            front = net["tools"][0]
            front["tools"] = [peer]
            net["link_labels"] = {peer: "tgtrust Trust Desk"}
            man["allowed_peers"] = [desk_url.rstrip("/")]
            if demo_patch:
                demo_patch(net, man, desk_url, extra_url)
            _write(net_path, net)
            _write(man_path, man)
            with serve(demo_dir, open_as="localhost", log=demo_log) as demo_url:
                yield desk_url, demo_url, desk_log, demo_log, extra_url
        finally:
            if extra_ctx:
                extra_ctx.__exit__(None, None, None)


class Visit:
    """One visitor tab: records every request the browser makes and blocks hosts other than the local ones."""

    def __init__(self, browser, url: str, *, otari_to: MockRouter | None = None):
        self.ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        self.requests: list[dict] = []
        self.blocked: list[str] = []
        self.otari_to = otari_to
        self.ctx.on("request", self._on_request)
        self.ctx.route(lambda u: urlsplit(u).hostname not in ("127.0.0.1", "localhost"), self._outside)
        self.page = self.ctx.new_page()
        self.errors: list[str] = []
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.goto(url)

    def _on_request(self, req):
        self.requests.append({"url": req.url, "method": req.method, "headers": dict(req.headers),
                              "body": req.post_data or ""})

    def _outside(self, route):
        url = route.request.url
        if self.otari_to and url.startswith("https://api.otari.ai/api/v1/"):
            # The site's default router: answered by the scripted router, so the default path can run offline.
            target = self.otari_to.url + url[len("https://api.otari.ai/api/v1"):]
            return route.fulfill(response=route.fetch(url=target))
        self.blocked.append(url)
        return route.abort("blockedbyclient")

    def ready(self):
        self.page.wait_for_selector("#ns-apply", state="attached", timeout=20000)

    def apply(self, router: str | None, model: str | None = "test-model"):
        self.ready()
        self.page.evaluate(
            """([key, router, model]) => {
              const set = (id, v) => { const el = document.querySelector(id); el.value = v;
                el.dispatchEvent(new Event("input", { bubbles: true })); };
              set("#ns-key", key);
              if (router !== null) set("#ns-router", router);
              if (model !== null) set("#ns-model", model);
              document.querySelector("#ns-apply").click();
            }""", [KEY, router, model])
        self.page.wait_for_load_state("load")
        self.page.wait_for_function("k => window.__nsweb && window.__nsweb.engine && window.__nsweb.engine.byokKey === k",
                                    arg=KEY, timeout=20000)

    def send(self, text: str):
        self.page.fill("#ns-input", text)
        self.page.click("#ns-send")

    def card(self, timeout=20000):
        self.page.wait_for_selector(".ns-consent .ns-consent-actions button", timeout=timeout)
        return self.page.inner_text(".ns-consent")

    def answer(self, decision: str):
        self.page.click(f".ns-consent .ns-consent-actions button[data-d={decision}]")

    def final(self, prefix: str, timeout=30000) -> str:
        loc = self.page.locator("#ns-msgs .ns-msg.bot", has_text=prefix).last
        loc.wait_for(timeout=timeout)
        return loc.inner_text()

    def to(self, base: str) -> list[dict]:
        origin = base.rstrip("/")
        return [r for r in self.requests if r["url"].startswith(origin)]

    def close(self):
        self.ctx.close()


def _assert_key_only_to_router(visit: Visit, router: MockRouter, own: str | None = None,
                               router_url: str | None = None):
    """The key goes only to the router. On a loopback host the runtime also mirrors the saved setup into a cookie
    for its own host name (spec section 4, "Reference storage"), so the caller's own origin may get it there, in
    the Cookie header only. The peer is on another host name and must never get it."""
    for r in visit.requests:
        text = r["url"] + json.dumps(r["headers"]) + r["body"]
        if KEY not in text:
            continue
        if own and r["url"].startswith(own.rstrip("/")):
            assert KEY not in r["url"] and KEY not in r["body"]
            assert KEY in r["headers"].get("cookie", "") and "authorization" not in r["headers"], r["url"]
            continue
        if KEY in text:
            assert r["url"].startswith(router_url or router.url.rsplit("/v1", 1)[0]), r["url"]
            assert KEY not in r["url"] and KEY not in r["body"]
            assert r["headers"].get("authorization") == f"Bearer {KEY}"
    for rec in router.chats():
        assert KEY not in rec["messages_text"], "the key reached a prompt"


# ---- 6.2 and 6.4: run with the default router and with BYOK; load a named network from a second origin ----------

def test_second_origin_after_consent_key_and_router_stay_with_caller(browser, tmp_path):
    with MockRouter(KEY, plan=["inspect", "desk"]) as router, sites(tmp_path) as (desk, demo, desk_log, demo_log, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.page.wait_for_selector("html[data-demo-ready=true]")
            v.send("Should we serve the request in the queue, and on what terms?")
            card = v.card()
            # Consent names the peer and its origin before any contact.
            assert "tgtrust Trust Desk" in card and urlsplit(desk).netloc in card
            assert v.to(desk) == [] and _log(desk_log) == []
            v.answer("allow")
            text = v.final("CALLER_FINAL")
            assert "DESK_ANSWER" in text, text
            # The exact named network was fetched from the second origin, with no credentials.
            fetched = {e["path"] for e in _log(desk_log)}
            assert {"/agent-manifest.json", "/trust_desk.network.json", "/links.json"} <= fetched
            for e in _log(desk_log):
                assert e.get("authorization") in (False, None) and not e.get("cookies"), e
            for r in v.to(desk):
                assert "authorization" not in r["headers"] and "cookie" not in r["headers"], r
            # The peer ran in this browser, on the caller's router, model and key.
            chats = router.chats()
            peer_calls = [c for c in chats if c["first_line"].startswith("You are the assistant on the tgtrust Trust Desk")]
            assert len(peer_calls) == 1
            assert peer_calls[0]["roles"] == ["system", "user"], "the peer gets only the request, no chat history"
            assert all(c["key_ok"] and c["model"] == "test-model" for c in chats)
            # The peer's manifest names hosted Otari as its router; nothing went there.
            assert not [u for u in v.blocked if "otari" in u]
            _assert_key_only_to_router(v, router, own=demo)
            assert v.errors == []
        finally:
            v.close()


def test_default_router_and_model_on_trust_desk_with_grounded_action(browser, tmp_path):
    """Trust Desk's own page: default router (hosted Otari, answered by the scripted router) and model, an internal
    agent, and the grounded site action."""
    with MockRouter(KEY) as router, sites(tmp_path) as (desk, _demo, _l1, _l2, _):
        v = Visit(browser, desk, otari_to=router)
        try:
            v.apply(router=None, model=None)  # key only: the site's published router and model
            v.page.wait_for_selector("html[data-desk-ready=true]")
            v.page.click("[data-sample=fresh]")
            v.page.locator("#result-meta", has_text="Checked").wait_for()
            key = v.page.get_attribute("#result-key", "title")
            v.send(f"Check agent {key}")
            text = v.final("DESK_FINAL")
            assert '"state":"partial"' in text.replace(" ", "") or "partial" in text
            chats = router.chats()
            assert chats[0]["first_line"].startswith("You are the assistant on the tgtrust Trust Desk website.")
            assert chats[1]["first_line"].startswith("You check evidence for the tgtrust Trust Desk assistant.")
            assert chats[0]["tools"][:2] == ["evidence_checker", "limit_advisor"] or "evidence_checker" in chats[0]["tools"]
            assert "website_check_agent" in chats[1]["tools"]
            assert all(c["model"] == "alibaba/qwen3.8-flash" and c["key_ok"] for c in chats)
            assert any(r["url"].startswith("https://api.otari.ai/api/v1/chat/completions") for r in v.requests)
            _assert_key_only_to_router(v, router, own=desk, router_url="https://api.otari.ai/api/v1/")
        finally:
            v.close()


def test_decline_sends_nothing_to_the_peer(browser, tmp_path):
    with MockRouter(KEY, plan=["desk"]) as router, sites(tmp_path) as (desk, demo, desk_log, _l, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.send("Ask Trust Desk which tier an agent with a proven key gets.")
            v.card()
            v.answer("decline")
            text = v.final("CALLER_FINAL")
            assert "declined" in text
            assert v.to(desk) == [] and _log(desk_log) == []
        finally:
            v.close()


# ---- 6.6: private context ----------------------------------------------------------------------------------

def _run_with_private_context(v: Visit):
    v.page.evaluate("""() => { window.__turn = window.__nsweb.engine.runTurn("Ask Trust Desk.",
        { slyData: { request_id: "r-1", api_customer_token: "SLY-PRIVATE-DO-NOT-SHARE" } }); }""")
    v.card()
    v.answer("allow")
    v.page.evaluate("() => window.__turn")
    calls = v.page.evaluate("""() => window.__nsweb.trace.events
        .filter(e => e.kind === "remote_call" && e.phase === "start")
        .map(e => Object.keys((e.requestPayload || {}).sly_data || {}))""")
    return calls


def test_private_context_reaches_the_peer_only_when_named(browser, tmp_path):
    with MockRouter(KEY, plan=["desk"]) as router, sites(tmp_path) as (_desk, demo, _l1, _l2, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            assert _run_with_private_context(v) == [["request_id"]]
            assert "SLY-PRIVATE" not in json.dumps(router.records)
        finally:
            v.close()

    def no_allow(net, man, desk, extra):
        net["tools"][0].pop("allow", None)

    with MockRouter(KEY, plan=["desk"]) as router, sites(tmp_path / "b", demo_patch=no_allow) as (_d, demo, _a, _b, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            assert _run_with_private_context(v) == [[]]
        finally:
            v.close()


# ---- 6.7: invalid network, composition cycle, over-budget request, denied origin --------------------------------

def test_wrong_network_name_fails_instead_of_another_network(browser, tmp_path):
    with MockRouter(KEY, plan=["desk"]) as router, sites(tmp_path, peer_url_name="trust_desk_v0") as (desk, demo, log, _l, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.send("Ask Trust Desk.")
            v.card()
            v.answer("allow")
            text = v.final("CALLER_FINAL")
            assert "No published network named 'trust_desk_v0'" in text, text
            assert {e["path"] for e in _log(log)} == {"/agent-manifest.json"}
            assert not [c for c in router.chats() if "Trust Desk website" in c["first_line"]]
        finally:
            v.close()


def test_invalid_peer_network_is_stopped_before_any_model_call(browser, tmp_path):
    def broken(desk_dir: Path):
        net = _read(desk_dir / "trust_desk.network.json")
        net["tools"][0]["tools"] = ["evidence_checker", "no_such_agent"]
        _write(desk_dir / "trust_desk.network.json", net)

    with MockRouter(KEY, plan=["desk"]) as router, sites(tmp_path, desk_patch=broken) as (_desk, demo, _l1, _l2, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.send("Ask Trust Desk.")
            v.card()
            v.answer("allow")
            text = v.final("CALLER_FINAL")
            assert "Error from tool" in text and "no_such_agent" in text, text
            assert not [c for c in router.chats() if "Trust Desk website" in c["first_line"]]
        finally:
            v.close()


def test_invalid_own_network_stops_with_a_visible_error(browser, tmp_path):
    def broken(net, man, desk, extra):
        net["tools"][0]["tools"].append("no_such_agent")

    with MockRouter(KEY) as router, sites(tmp_path, demo_patch=broken) as (_desk, demo, _l1, _l2, _):
        v = Visit(browser, demo)
        try:
            status = v.page.locator("#assistant-status", has_text="could not load")
            status.wait_for(timeout=20000)
            assert "no_such_agent" in status.inner_text()
            assert router.records == []
        finally:
            v.close()


def test_second_call_to_the_same_peer_is_over_budget(browser, tmp_path):
    with MockRouter(KEY, plan=["desk", "desk_again"]) as router, sites(tmp_path) as (_desk, demo, _l1, _l2, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.send("Ask Trust Desk twice.")
            v.card()
            v.answer("always")
            text = v.final("CALLER_FINAL")
            assert "DESK_ANSWER" in text and "Skipped tgtrust Trust Desk:" in text, text
            assert len([c for c in router.chats() if "Trust Desk website" in c["first_line"]]) == 1
        finally:
            v.close()


def _loop_fixture(served: Path, sub: str):
    """A network whose front agent names its own URL. Returns a demo_patch that writes it under served/sub."""
    folder = served / sub if sub else served
    folder.mkdir(parents=True, exist_ok=True)

    def patch(net, man, desk, extra):
        url = f"{extra}{sub + '/' if sub else ''}loop_peer"
        net["tools"][0]["tools"] = [url]
        net["link_labels"] = {url: "Loop fixture"}
        man["allowed_peers"] = [extra.rstrip("/")]
        own = {"metadata": {"description": "LOOP_PEER fixture"}, "llm_config": {"model_name": "test-model"},
               "link_labels": {url: "Loop fixture"},
               "tools": [{"name": "loop_peer", "function": {"description": "Loops", "parameters": {
                   "type": "object", "properties": {"request": {"type": "string"}}, "required": ["request"]}},
                   "instructions": "LOOP_PEER: call yourself.", "tools": [url]}]}
        _write(folder / "loop_peer.network.json", own)
        _write(folder / "links.json", {"version": 1, "networks": {"loop_peer": {}}})
        _write(folder / "agent-manifest.json", {
            "brand": "Loop fixture", "networks": [{"name": "loop_peer", "front_man": "loop_peer",
                                                    "hocon": "./loop_peer.network.json"}],
            "llm_router": {"base_url": "https://api.otari.ai/api/v1", "mock": False},
            "allowed_peers": [extra.rstrip("/")], "peer_policy": {"mode": "closed"},
            "deployment": {"mode": "static"}})

    return patch


def _run_loop(browser, tmp_path, sub: str):
    served = tmp_path / "loopsrv"
    served.mkdir()
    with MockRouter(KEY, plan=["desk"]) as router, sites(tmp_path, demo_patch=_loop_fixture(served, sub),
                                                         extra_peer=served) as (_d, demo, _a, _b, _e):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.send("Run the loop.")
            v.card()
            v.answer("allow")
            return v.final("CALLER_FINAL"), router
        finally:
            v.close()


def test_composition_cycle_is_stopped_with_a_visible_error(browser, tmp_path):
    """Under a subpath, as on GitHub Pages, the loop network is offered its own URL. When it calls itself the runtime
    skips the call and says so. The skip comes from the per-message limit of one call per peer network
    (runner.js consumeRemoteBudget), which the runtime checks before its cycle detector (remote.js checkCycle);
    either way the loop does not run again."""
    text, router = _run_loop(browser, tmp_path, "sites")
    assert "LOOP_ANSWER: Skipped Loop fixture: that network was already consulted for this query" in text, text
    loops = [c for c in router.chats() if "LOOP_PEER" in c["first_line"]]
    assert len(loops) == 2, "the loop network ran once, called itself, and got the skip"


def test_composition_cycle_at_a_site_root_is_never_offered(browser, tmp_path):
    """At a site root the runtime does not even offer a network a tool that points back into the call chain."""
    text, router = _run_loop(browser, tmp_path, "")
    assert "LOOP_ANSWER: no tool" in text, text
    loops = [c for c in router.chats() if "LOOP_PEER" in c["first_line"]]
    assert len(loops) == 1 and "loop_peer" not in loops[0]["tools"]


def test_denied_origin_is_refused_with_a_visible_error(browser, tmp_path):
    def deny(net, man, desk, extra):
        man["allowed_peers"] = []

    with MockRouter(KEY, plan=["desk"]) as router, sites(tmp_path, demo_patch=deny) as (desk, demo, log, _l, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.send("Ask Trust Desk.")
            v.card()
            v.answer("allow")
            text = v.final("CALLER_FINAL")
            assert "is not in paid_api_desk's allowed_peers; refusing to contact it" in text, text
            assert v.to(desk) == [] and _log(log) == []
        finally:
            v.close()


# ---- 3.1: an irreversible write is confirmed by the visitor; an unknown outcome is never retried ---------------

def test_write_with_unknown_outcome_is_reported_unknown_and_not_retried(browser, tmp_path):
    with MockRouter(KEY, plan=["inspect", "serve"]) as router, sites(tmp_path) as (_desk, demo, _l1, _l2, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.page.wait_for_selector("html[data-demo-ready=true]")
            v.page.check("#simulate-timeout")
            v.send("Serve the request in the queue on prepay.")
            dialog = v.page.locator("dialog.assistant-review[open]")
            dialog.wait_for(timeout=20000)
            details = dialog.inner_text()
            assert "Serve this request?" in details and "prepay" in details
            dialog.locator("summary").click()
            assert f"serve_request on {demo.rstrip('/')}" in dialog.inner_text()
            dialog.get_by_role("button", name="Serve the request").click()
            text = v.final("CALLER_FINAL", timeout=40000)
            assert '"status":"unknown"' in text.replace(" ", ""), text
            assert v.page.text_content("#serve-calls") == "1"
            serves = [c for c in router.chats() if c["reply"].get("tool") == "website_serve_request"]
            assert len(serves) == 1
        finally:
            v.close()


def test_declined_write_runs_nothing(browser, tmp_path):
    with MockRouter(KEY, plan=["inspect", "serve"]) as router, sites(tmp_path) as (_desk, demo, _l1, _l2, _):
        v = Visit(browser, demo)
        try:
            v.apply(router.url)
            v.page.wait_for_selector("html[data-demo-ready=true]")
            v.send("Serve the request in the queue on prepay.")
            dialog = v.page.locator("dialog.assistant-review[open]")
            dialog.wait_for(timeout=20000)
            dialog.get_by_role("button", name="Don't serve").click()
            text = v.final("CALLER_FINAL")
            assert '"status":"cancelled"' in text.replace(" ", ""), text
            assert v.page.text_content("#serve-calls") == "0"
            assert v.page.text_content("#q-status") == "waiting"
        finally:
            v.close()


# ---- 4: BYOK — missing key, deletable profile ------------------------------------------------------------------

def test_missing_key_stops_the_model_call_with_a_setup_error(browser, tmp_path):
    with MockRouter(KEY) as router, sites(tmp_path) as (desk, _demo, _l1, _l2, _):
        v = Visit(browser, desk)
        try:
            v.ready()
            v.send("Check agent " + "ab" * 32)
            msg = v.page.locator("#ns-msgs .ns-msg.bot", has_text="API key").last
            msg.wait_for(timeout=10000)
            assert router.records == []
            assert not [u for u in v.blocked if "chat/completions" in u]
        finally:
            v.close()


def test_saved_setup_can_be_deleted(browser, tmp_path):
    with MockRouter(KEY) as router, sites(tmp_path) as (desk, _demo, _l1, _l2, _):
        v = Visit(browser, desk)
        try:
            v.apply(router.url)
            stored = v.page.evaluate("() => JSON.stringify(Object.assign({}, localStorage)) + document.cookie")
            assert KEY in stored
            v.page.evaluate("() => { document.querySelector('.ns-settings').open = true;"
                            " document.querySelector('.ns-settings-advanced').open = true; }")
            v.page.click("#ns-delete-profile")
            v.page.locator("text=Deleted setup").first.wait_for()
            # The stored profile is gone from localStorage and from the loopback cookie mirror.
            assert KEY not in v.page.evaluate("() => JSON.stringify(Object.assign({}, localStorage)) + document.cookie")
            # The setup applied in this tab lives in its sessionStorage until the tab closes (runtime/byok.js);
            # a new tab starts with no key.
            v.page.close()
            fresh = v.ctx.new_page()
            fresh.goto(desk)
            fresh.wait_for_selector("#ns-apply", state="attached")
            stored = fresh.evaluate("() => JSON.stringify(Object.assign({}, localStorage)) + JSON.stringify("
                                    "Object.assign({}, sessionStorage)) + document.cookie")
            assert KEY not in stored
            assert fresh.evaluate("() => window.__nsweb.engine.byokKey || ''") in ("", "demo")
        finally:
            v.close()


def test_published_demo_points_at_the_public_trust_desk():
    net = _read(DEMO / "paid_api_desk.network.json")
    man = _read(DEMO / "agent-manifest.json")
    assert net["tools"][0]["tools"] == [PUBLIC_DESK]
    assert man["allowed_peers"] == ["https://miinimal.github.io"]
    assert net["tools"][0]["allow"] == {"to_downstream": {"sly_data": ["request_id"]}}
