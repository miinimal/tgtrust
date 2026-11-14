"""The Pages workflow publishes desk/ without tests or build tools, keeps .well-known/, and runs only from main."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")


def test_pages_publishes_only_the_site():
    assert "cp -R desk/. _site/" in WORKFLOW
    assert "rm -rf _site/tests _site/tools" in WORKFLOW
    assert "touch _site/.nojekyll" in WORKFLOW
    assert 'grep -rl "seed_hex" _site' in WORKFLOW


def test_pages_runs_from_main_only_with_least_permissions():
    assert "branches: [main]" in WORKFLOW and "pull_request" not in WORKFLOW
    assert "pages: write" in WORKFLOW and "id-token: write" in WORKFLOW and "contents: read" in WORKFLOW
    assert "contents: write" not in WORKFLOW


def test_site_works_under_the_pages_subpath(tmp_path):
    """Assemble _site as the workflow does and open it under /tgtrust/, the path Pages serves it from."""
    import shutil

    import pytest

    sync_api = pytest.importorskip("playwright.sync_api")
    from .desk_server import serve_static

    site = tmp_path / "tgtrust"
    shutil.copytree(ROOT / "desk", site, ignore=shutil.ignore_patterns("tests", "tools"))
    (site / ".nojekyll").touch()
    with serve_static(tmp_path) as base, sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as exc:  # browser binary not installed
            pytest.skip(f"Chromium is not available: {exc}")
        ctx = browser.new_context()
        ctx.route(lambda u: not u.startswith(base), lambda route: route.abort("blockedbyclient"))
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(base + "tgtrust/")
        page.wait_for_selector("html[data-desk-ready=true]")
        page.locator("#assistant-status", has_text="AI provider key").wait_for(timeout=20000)
        page.click("[data-sample=forged]")
        page.locator("#result-meta", has_text="Checked").wait_for()
        assert page.text_content("#result-state") == "Invalid"
        assert page.text_content("#network-url") == base + "tgtrust/trust_desk"
        for name in ("agent-manifest.json", "trust_desk.network.json", "links.json", ".well-known/nsdeploy.json"):
            resp = page.request.get(base + "tgtrust/" + name)
            assert resp.ok, name
        assert errors == []
        browser.close()


def test_nothing_published_names_a_secret():
    published = [p for p in (ROOT / "desk").rglob("*")
                 if p.is_file() and "tests" not in p.parts and "tools" not in p.parts]
    for path in published:
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "seed_hex" not in text, path
        assert "PRIVATE KEY" not in text, path
        assert not re.search(r"otk_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{20,}", text), path
