# Changelog

## v0.2.0 — 2026-11-13

Agent-to-agent trust you can use from a paid API, an MCP client or an agent card. Still a reference implementation on testnets; not audited.

- Trust gate for paid agent APIs (`tgtrust.gate`, docs/TRUST_GATE.md): agents sign requests with their key; the API gives prepay or credit by tgtrust level, stake, upheld disputes and the Concordium badge; x402 v2 extension `tgtrust` (`x402_extension`, `{info, schema}`) and `extra.tgtrust` for v1 (`x402_extra`).
- Paid API example (`examples/paid_api.py`): anonymous refused, verified prepays with an x402 v2 `402`, staked runs on credit up to its limit.
- `check --card <file | https URL | https origin>`: checks an agent from its A2A card (`/.well-known/agent-card.json`) or ERC-8004 file; a card is treated as a claim.
- docs/SUBMISSION.md and docs/DEMO.md for the Concordium Trusted Agents entry.
- `python -m tgtrust.client check --agent <key>`: prints another agent's trust card; exit 0 only for `verified` or `staked`. Issuer from `--url` or `TGTRUST_ISSUER_URL`.
- Concordium Agent Registry link: `concordium-bind` signs a CIS-8 binding of the agent key to a Concordium account; `check --concordium` reads the binding and the badge (docs/CONCORDIUM.md).
- MCP server (stdio, read-only): `tgtrust_check_agent`, `tgtrust_concordium_link`.
- ERC-8004 export: `--concordium-badge` adds the CIS-8004 registration and the Concordium and tgtrust A2A extensions, after reading the badge from the chain.
- OpenClaw / ClawHub skill in `skills/tgtrust/SKILL.md`.
- Real Telegram-signed init data checked on 2026-11-12 (docs/REAL_TELEGRAM_CHECK.md).
- Badge bot survives dropped connections and messages it cannot answer; the bot token is never written to stderr.
- Stake lookup reports every network failure as a lookup error.

## v0.1.0 — 2026-11-12

First public version. Reference implementation on TON testnet; not audited.

- Telegram Mini App init data check with Telegram's Ed25519 signature (third-party validation).
- Blind-signed credentials, RFC 9474 RSABSSA-SHA384-PSSZERO-Deterministic: one credential per Telegram
  account per issuer epoch; the issuer keeps only an HMAC pseudonym and cannot link a credential to an account.
- Agent registry: a credential bound to an Ed25519 agent key through a single-use challenge.
- `StakeRegistry` contract in Tolk: deposit, cooldown withdrawal, arbiter slash; 23 sandbox tests; deployed
  on testnet with a full deposit → slash → withdraw run recorded.
- Trust badge (`GET /v1/agents/{key}/badge`): levels `unknown`, `revoked`, `verified`, `staked`, with deal
  and dispute history.
- Deals ledger with signatures of both parties; disputes with an arbiter verdict that maps to an on-chain slash.
- Holder Mini App at `/app/`: get a credential in the browser, blind signing done client-side.
- Agent SDK and CLI, badge bot, two-agent example, ERC-8004 registration file export.
- HTTP service hardening: 16 KB body cap (also for chunked bodies), strict base64url, input bounds, error
  bodies that never echo input, per-client rate limit that takes the proxy-added `X-Forwarded-For` entry and
  forgets idle clients.
- Docker image and compose file for the issuer and the bot.
