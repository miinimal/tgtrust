# Changelog

## Unreleased

- `python -m tgtrust.client check --agent <key>`: prints another agent's trust card; exit 0 only for `verified` or `staked`. Issuer from `--url` or `TGTRUST_ISSUER_URL`.
- Concordium Agent Registry link: `concordium-bind` signs a CIS-8 binding of the agent key to a Concordium account; `check --concordium` reads the binding and the badge (docs/CONCORDIUM.md).
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
