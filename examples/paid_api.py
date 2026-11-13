"""A paid agent API that prices callers by trust: x402 v2 reply with the tgtrust extension.

    python examples/paid_api.py

One endpoint, ``POST /v1/answer``, priced at 100 units per call. The trust gate decides per request:

- an anonymous caller is refused;
- an agent with a credential but no stake must pay first (``402`` with x402 ``PAYMENT-REQUIRED``);
- an agent with enough Gram at stake may run up to 1,000 units of credit and pay later.

Badges come from a dict in this process (demo data, no network). Against a real issuer use
``gate_for_issuer("https://<issuer>/v1", POLICY)`` instead. The example takes no payment itself: a real API hands
the x402 ``PAYMENT-SIGNATURE`` header to its facilitator. ``X402_ASSET`` and ``X402_PAY_TO`` must be set to your own
token contract and receiving address before anything real is paid.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tgtrust import gate
from tgtrust.client import AgentIdentity

PRICE = 100  # the API's own smallest unit per call
NETWORK = "eip155:84532"  # Base Sepolia, CAIP-2 (x402 v2 spec, section 11.1)
ASSET = os.environ.get("X402_ASSET", "<token contract on NETWORK>")
PAY_TO = os.environ.get("X402_PAY_TO", "<your receiving address>")

POLICY = gate.Policy(
    anonymous=gate.Tier("anonymous", allowed=False),
    unknown=gate.Tier("unknown", prepay=True),
    verified=gate.Tier("verified", prepay=True),
    staked=gate.Tier("staked", prepay=False, credit_limit=1_000),
    min_stake_nanogram=500_000_000,
    max_upheld_disputes=0,
)


def payment_required(request: Request, decision: gate.Decision, error: str) -> dict:
    """The x402 v2 PaymentRequired object (sent base64 in the PAYMENT-REQUIRED header)."""
    return {
        "x402Version": 2,
        "error": error,
        "resource": {"url": str(request.url), "description": "One answer", "mimeType": "application/json"},
        "accepts": [{"scheme": "exact", "network": NETWORK, "amount": str(PRICE), "asset": ASSET,
                     "payTo": PAY_TO, "maxTimeoutSeconds": 60}],
        "extensions": gate.x402_extension(decision),
    }


def create_app(trust_gate: gate.TrustGate) -> FastAPI:
    app = FastAPI()
    credit_used: dict[str, int] = {}

    @app.post("/v1/answer")
    async def answer(request: Request):
        body = await request.body()
        path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        decision = trust_gate.decide(request.method, path, dict(request.headers), body)
        if not decision.allowed:
            return JSONResponse({"error": "refused", "tier": decision.tier.name, "evidence": decision.evidence},
                                status_code=403)
        if request.headers.get("payment-signature"):
            # A real API verifies and settles this with its x402 facilitator before answering.
            return JSONResponse({"error": "this example does not settle payments"}, status_code=501)
        used = credit_used.get(decision.agent or "", 0)
        if decision.tier.prepay or used + PRICE > decision.tier.credit_limit:
            why = "prepay required for this tier" if decision.tier.prepay else "credit limit reached"
            pr = payment_required(request, decision, why)
            header = base64.b64encode(json.dumps(pr, separators=(",", ":")).encode()).decode()
            return JSONResponse({}, status_code=402, headers={"PAYMENT-REQUIRED": header})
        credit_used[decision.agent] = used + PRICE
        return {"answer": 42, "tier": decision.tier.name, "credit_used": credit_used[decision.agent],
                "credit_limit": decision.tier.credit_limit, "evidence": decision.evidence}

    return app


def demo_badge(key: str, level: str, stake_nanogram: int | None = None) -> dict:
    badge = json.loads((Path(__file__).parent / "card" / "badge-alice.json").read_text())
    badge.update(agent=key, level=level)
    if stake_nanogram is not None:
        badge["stake"] = {"network": "testnet", "found": True, "amount_nanogram": stake_nanogram,
                          "withdrawing": False}
    return badge


def run_demo() -> list[tuple[str, int, dict]]:
    from fastapi.testclient import TestClient

    verified, staked = AgentIdentity.generate(), AgentIdentity.generate()
    badges = {verified.hex: demo_badge(verified.hex, "verified"),
              staked.hex: demo_badge(staked.hex, "staked", stake_nanogram=600_000_000)}
    trust_gate = gate.TrustGate(lambda key: copy.deepcopy(badges[key]), POLICY)
    client = TestClient(create_app(trust_gate))
    body = b'{"q":"meaning of life"}'

    def call(agent: AgentIdentity | None) -> tuple[int, dict]:
        headers = gate.sign_request(agent, "POST", "/v1/answer", body) if agent else {}
        r = client.post("/v1/answer", content=body, headers=headers)
        if r.status_code == 402:
            return 402, json.loads(base64.b64decode(r.headers["PAYMENT-REQUIRED"]))
        return r.status_code, r.json()

    results = [("anonymous", *call(None)), ("verified, no stake", *call(verified))]
    for i in range(11):
        results.append((f"staked, call {i + 1}", *call(staked)))
    return results


if __name__ == "__main__":
    for who, status, data in run_demo():
        if status == 402:
            info = data["extensions"]["tgtrust"]["info"]
            print(f"{who:20} 402  tier={info['tier']['name']:9} {data['error']}")
        elif status == 200:
            print(f"{who:20} 200  tier={data['tier']:9} credit {data['credit_used']}/{data['credit_limit']}")
        else:
            print(f"{who:20} {status}  {data.get('error')}")
