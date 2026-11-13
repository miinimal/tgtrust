# tgtrust — anonymous, accountable AI agents for Telegram on TON

**Check it yourself:** [verify an agent in 60 seconds](docs/VERIFY_IN_60_SECONDS.md) (copy-paste commands, demo data, offline after install).

Telegram is becoming a society of agents: bots create bots (Bot API 9.6), bots talk to bots (Bot API 10.0),
agents hold TON wallets. Nobody can tell whether an agent holds a credential from a Telegram-checked issuer and has anything at stake. Reputation
scores are cheap to farm, identity checks reveal the owner.

tgtrust lets an agent prove three facts **without revealing who stands behind it**:

1. **It holds an issuer credential, one Telegram account per issuer epoch** — owner identity is not checked and not revealed; proven with
   Telegram's own Ed25519 signature on Mini App init data and an RFC 9474 blind signature, so the issuer
   cannot link the credential to the account.
2. **Its owner has Gram at stake** — locked in the `StakeRegistry` contract on TON, slashed by an arbiter
   verdict, withdrawable after a cooldown. The badge shows the amount, never the wallet.
3. **It has a history** — deals confirmed by both parties' signatures, disputes filed and upheld.

A bot asks one question — `GET /v1/agents/{key}/badge` — and gets a level: `unknown`, `revoked`,
`verified` (issuer credential, one Telegram account per issuer epoch), `staked` (credential and Gram at risk on TON testnet), plus the numbers behind it.

## Status (2026-11-12)

| Part | State |
| --- | --- |
| Telegram signature check, blind-signed credentials, issuer service | done; whole Python suite: 353 tests (signatures checked with a stand-in key; see `docs/REAL_TELEGRAM_CHECK.md`) |
| Agent registry (credential bound to the agent key) | done |
| `StakeRegistry` contract (Tolk 1.5) | done, 23 sandbox tests; testnet `kQD0dNGo6GJnxq7Dc5HWcEfoBWI8UkUwZ6-w7gpwm8G11z-w` |
| Trust badge, deals ledger, disputes with on-chain slash | done |
| ERC-8004 registration file export (`python -m tgtrust.erc8004`, see docs/ERC8004_EXPORT.md) | done, not yet registered on any EVM registry |
| Agent SDK and two-agent example | done |
| Holder Mini App at `/app/`: credential in the browser, no code needed (see docs/HOLDER_MINI_APP.md) | done; tested in Chromium with a stand-in Telegram key, not yet opened in a real Telegram client |
| Real init data signed by Telegram | checked 2026-11-12 with `python -m tgtrust.telegram_sig` on init data from a live Mini App: the real string verified with Telegram's production key; a wrong bot id and an altered user field were rejected (see docs/REAL_TELEGRAM_CHECK.md) |
| Concordium Agent Registry link (`concordium-bind`, `check --concordium`, docs/CONCORDIUM.md): bind the agent key to an identified Concordium account through CIS-8 | done; byte format matches the registry, reads tested on live testnet; no key bound on testnet yet |
| OpenClaw / ClawHub skill (`skills/tgtrust/SKILL.md`): any agent checks another agent with `python -m tgtrust.client check --agent <key>` | done, tested locally; not yet published on ClawHub |
| Mainnet | not before an external audit |

The code is a working reference implementation of the standard, not a finished product: the issuer is a
single trusted party in this phase (path A); path B replaces it with a zero-knowledge proof of Telegram's
signature.

## Verify it yourself

```
git clone https://github.com/miinimal/tgtrust && cd tgtrust
pip install -e ".[dev,browser]" && playwright install chromium && pytest   # whole suite: issuance, binding, deals, disputes, abuse cases
python examples/two_agents.py                      # two agents: register, deal, dispute, verdict
cd contracts && npm ci && npm test                 # 23 contract tests, every cheating scenario
```

On chain: open the testnet contract in any explorer and read `get_stake` for agent
`738559c16db0b6b80b73de6094744bd9e802fb7df4657b3f41fdd3c7238228d8` — a demo stake left after a slash with case id
`2484130606561302757` (`contracts/deployments/testnet-cycle.log` has the full deposit → slash → withdraw run).

## How it works

**Credential.** The holder opens the issuer's Mini App (`/app/`, see [docs/HOLDER_MINI_APP.md](docs/HOLDER_MINI_APP.md)); Telegram signs the init data. The holder blinds a token
that commits to its agent key (`SHA-256(prefix || agent_key || salt)`), the issuer verifies Telegram's
signature, checks that the account has no credential this epoch (it stores only an HMAC pseudonym of the
account) and blind-signs. The unblinded signature verifies as standard RSASSA-PSS and cannot be linked back.

**Registration.** The agent presents the credential, the salt and a signature over a single-use challenge.
The registry keeps the agent key, a hash of the token, the issuer key id and the time — nothing about the
account. A stolen credential is useless: it only ever binds to the key it was issued for.

**Stake.** The owner sends `Deposit` to `StakeRegistry` with the agent's signed consent (bound to the contract
and the owner, so it cannot be replayed). `RequestWithdraw` starts the cooldown, during which the stake stays
slashable; `Withdraw` pays out after it. `Slash` is arbiter-only, splits between the victim and the treasury,
and burns a one-time case id. Every payout is bounceable and recoverable; the contract balance always covers
all stakes. Admin and arbiter change only through delayed two-step proposals.

**Deals.** Two registered agents sign one canonical record (ordered keys, amount, time, memo hash). The ledger
stores whether each party was staked at the time, so "deals with staked counterparties" is the number that is
expensive to farm.

**Disputes.** A party files a case signed with its agent key, naming the accused and a payout address of its
choice. The arbiter signs a verdict with a separate key; an upheld verdict exposes the exact `Slash` fields.
The arbiter wallet executes it; the contract makes each case id single-use.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/issuer` | issuer key id, public key, scheme, policy |
| POST | `/v1/issue` | `{init_data, blinded_message}` → blind signature |
| POST | `/v1/verify` | `{token, signature}` → validity |
| POST | `/v1/challenge` | single-use registration challenge |
| POST | `/v1/register` | credential + agent key + challenge signature → badge |
| GET | `/v1/agents/{key}` | registration record |
| GET | `/v1/agents/{key}/badge` | **one call: level, Telegram check, stake, history** |
| POST | `/v1/deals` | two-party signed deal record |
| GET | `/v1/agents/{key}/deals` | deal stats and list |
| POST | `/v1/disputes` | file a case (claimant signature) |
| POST | `/v1/disputes/{id}/verdict` | arbiter-signed verdict |
| GET | `/v1/disputes/{id}`, `/v1/agents/{key}/disputes` | case and stats |

Contract getters: `get_stake(agent_key)`, `get_config()`, `get_governance()`, `get_totals()`,
`get_unclaimed(address)`, `is_case_used(case_id)`, `get_required_values()`. Full contract spec and measured
costs: [`contracts/README.md`](contracts/README.md). Deployment: [`deploy/`](deploy/README.md).

## Security notes

- The issuer learns a keyed pseudonym of the Telegram account, never the agent key it signs for; the registry
  learns the agent key, never the account. Linking the two needs both the issuer's pseudonym key and the
  holder's blinding secret, which never meet.
- Credentials are agent-bound; challenges are single-use and expire in 5 minutes; deal and dispute records are
  valid within ±1 hour of their timestamp and are replay-proof by id.
- The contract never trusts a bounce beyond the coins that actually returned; governance keys cannot move funds;
  the arbiter key is the residual risk and must be a multisig in production.
- Error codes, gas and storage figures are documented with sources and dates in the docs.

## Repository

```
tgtrust/        Python package: telegram_sig, blind_rsa, issuer, registry, service, stake, badge, deals, disputes, client, bot
contracts/      Tolk contract, TypeScript wrapper, sandbox tests, testnet scripts and deployment record
tests/          Python tests          examples/   two-agent lifecycle          deploy/   Docker, compose, runbook
docs/           threat model, 60-second verification, Mini App, ERC-8004 export, decisions
```

License: MIT. Author: Aleksandr Shcherbakov (@miinimal). Security reports: see SECURITY.md. Changes: CHANGELOG.md.
