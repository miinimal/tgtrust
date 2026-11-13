# Trust gate for paid agent APIs

An API that sells to agents has to decide on every request whether this caller must pay first, or whether it
may use the API on a small balance and pay afterwards. `tgtrust.gate` makes that decision from evidence the
caller cannot fake:

1. The caller signs the request with its tgtrust agent key, so the key is proven, not just claimed.
2. The gate reads that key's badge from the issuer and, if the policy asks for it, its Concordium Agent
   Registry link.
3. A `Policy` maps what was proven to a `Tier`: refused, prepay, or credit up to a limit.

The gate never moves money. A level the caller states about itself is never trusted. Every decision lists the
evidence it was made from.

## Caller

```python
from tgtrust.client import AgentIdentity
from tgtrust.gate import sign_request

headers = sign_request(agent, "POST", "/v1/answer?q=1", body)  # add to the HTTP request
```

| Header | Value |
| --- | --- |
| `X-Tgtrust-Agent` | agent public key, 64 hex characters |
| `X-Tgtrust-Time` | unix seconds; the server accepts ±120 s |
| `X-Tgtrust-Nonce` | 16–64 characters of `A-Z a-z 0-9 _ -`, never reused |
| `X-Tgtrust-Signature` | base64url Ed25519 signature over the bytes below |

The signed bytes (`tgtrust-req/v1`) are these lines joined with `\n`: `tgtrust-req/v1`, the method, the path
with its query, the time, the nonce, and the hex SHA-256 of the body. If any part of the request changes, the
signature no longer verifies. The server remembers each (agent, nonce) pair inside the time window, so a
captured request cannot be replayed.

## API

```python
from tgtrust.gate import Policy, Tier, gate_for_issuer, x402_extension

policy = Policy(
    anonymous=Tier("anonymous", allowed=False),
    unknown=Tier("unknown", prepay=True),
    verified=Tier("verified", prepay=True),
    staked=Tier("staked", prepay=False, credit_limit=1_000),                 # API's own smallest unit
    concordium_tier=Tier("staked+concordium", prepay=False, credit_limit=5_000),
    require_concordium="testnet",
    min_stake_nanogram=500_000_000,
    max_upheld_disputes=0,
)
gate = gate_for_issuer("https://trust.example.org/v1", policy)
decision = gate.decide(method, path, headers, body)
```

How a tier is chosen:

| Evidence | Tier |
| --- | --- |
| no tgtrust headers, or a bad, stale or replayed signature | `anonymous` (`decision.error` names the reason) |
| signature valid, but level `unknown` or `revoked`, the badge lookup failed, or more upheld disputes than allowed | `unknown` |
| level `verified`, or `staked` with less than `min_stake_nanogram` or a withdrawing stake | `verified` |
| level `staked` with enough active stake | `staked` |
| as above, and the key's CIS-8 binding is Active and its Verified by Concordium badge is valid | `concordium_tier` |

## x402 extra v1

When the API answers `402 Payment Required` through x402, describe the caller's tier with the object from
`x402_extra(decision, issuer_url=...)`. The object tells the caller which tier it got and which headers raise
it. The gate does not change any other x402 field. Fields: `extension` (this section's URI), `scheme`, `headers`,
`issuer`, `agent`, `level`, `tier` (`name`, `allowed`, `prepay`, `creditLimit` as a string), `error`.

Where it goes depends on the x402 version (x402 specification v2 read 2026-11-13 at
`github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md`):

| x402 | Place | Helper |
| --- | --- | --- |
| v2 (`x402Version: 2`, `PAYMENT-REQUIRED` header) | top-level `extensions.tgtrust` as `{"info": <object>, "schema": <JSON Schema>}`; v2 keeps `accepts[].extra` for scheme-specific keys | `x402_extension(decision, issuer_url=...)` |
| v1 | `extra.tgtrust` in each `PaymentRequirements` entry | `x402_extra(decision, issuer_url=...)` |

## Limits

- A tier is only as strong as its issuer. The Telegram check means one Telegram account per issuer epoch, not a
  checked person.
- The stake is on TON testnet in this phase.
- The credit limit is the API's own setting. The gate records nothing about debts.
