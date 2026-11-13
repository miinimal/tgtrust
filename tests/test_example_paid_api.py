"""examples/paid_api.py: refused, prepay, credit up to the limit, then 402 again."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("paid_api", ROOT / "examples" / "paid_api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_paid_api_demo_tiers_and_x402_v2_reply():
    results = _load().run_demo()
    by_who = {who: (status, data) for who, status, data in results}

    assert by_who["anonymous"][0] == 403

    status, pr = by_who["verified, no stake"]
    assert status == 402 and pr["x402Version"] == 2
    assert set(pr) == {"x402Version", "error", "resource", "accepts", "extensions"}
    assert set(pr["accepts"][0]) == {"scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds"}
    assert pr["accepts"][0]["network"] == "eip155:84532" and pr["accepts"][0]["amount"] == "100"
    ton = pr["accepts"][1]
    assert set(ton) == set(pr["accepts"][0])
    assert ton["scheme"] == "exact" and ton["network"] == "tvm:-3" and ton["asset"] == "native"
    assert ton["amount"] == "10000000" and ton["amount"].isdigit()
    info = pr["extensions"]["tgtrust"]["info"]
    assert info["tier"]["name"] == "verified" and info["tier"]["prepay"] is True
    assert set(pr["extensions"]["tgtrust"]) == {"info", "schema"}

    for i in range(1, 11):
        status, data = by_who[f"staked, call {i}"]
        assert status == 200 and data["tier"] == "staked" and data["credit_used"] == 100 * i
    status, pr = by_who["staked, call 11"]
    assert status == 402 and pr["error"] == "credit limit reached"
    assert pr["extensions"]["tgtrust"]["info"]["tier"]["creditLimit"] == "1000"
