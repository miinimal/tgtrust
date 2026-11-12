# tgtrust threat model (2026-11-12)

## Assets

1. Owner anonymity: the link between an agent key and the Telegram account behind it.
2. Staked Gram in `StakeRegistry`.
3. Integrity of trust signals: uniqueness, stake state, deal and dispute history.
4. Availability of the badge for bots that rely on it.

## Actors

- Holder/owner (honest or cheating), agent operator (may differ from the owner), counterparties, outsiders.
- Issuer operator, registry/ledger operator (same service in path A), arbiter, admin, treasury.
- Network observers (everything on chain and every HTTP call to the service is visible to someone).

## Attacks and mitigations

| # | Attack | Mitigation | Test / evidence |
| --- | --- | --- | --- |
| A1 | Issuer links a credential to a Telegram account | RFC 9474 blind signature: issuer signs a blinded token; it stores only HMAC(pseudonym key, account) | `test_issuer.py`, `test_blind_rsa.py` |
| A2 | One account backs many agents (sybil) | one credential per account per epoch; slot taken only after a successful signature | `test_issuer.py` |
| A3 | Stolen credential used by another agent | token commits to the agent key; registration needs a signed single-use 5-minute challenge | `test_registry.py` |
| A4 | Forged Telegram init data | Ed25519 verification against Telegram's published key, freshness window, duplicate-field rejection | `test_telegram_sig.py`, `test_telegram_cli.py` (stand-in key only; no string signed by Telegram has been checked, see `docs/REAL_TELEGRAM_CHECK.md`) |
| A5 | Occupy someone else's agent key with a stake (`Deposit`) | agent signs consent bound to contract address, owner address, key and nonce; replay fails elsewhere | contract tests: signature, replay by other owner / other contract |
| A6 | Non-owner tops up, requests or withdraws | owner checks on every owner op | contract tests |
| A7 | Cheat then withdraw at once | cooldown; stake stays slashable during it | contract test: slash during pending withdrawal |
| A8 | Slash by non-arbiter, over the stake, replayed | arbiter check, amount ≤ stake, one-time case id burned only on success | contract tests |
| A9 | Steal funds through governance | admin/arbiter cannot move funds; two-step changes with delay ≥ cooldown enforced on chain (exit 118) | contract tests: delay, wrong acceptor, misconfigured deploy |
| A10 | Lose coins through failed payouts | every payout bounceable; bounced coins credited to `unclaimed[dest]`, claimable; forged bounce credits only what arrived | contract tests: ghost victim, ghost treasury, claim |
| A11 | Drain contract through under-paid gas | required value from live config with ≥2× gas margin; shortfall rejected before any state change | contract tests: insufficient value, out of gas |
| A12 | Garbage or truncated messages | typed lazy parsing; unknown or malformed bodies throw and bounce; invariant checked after each | fuzz test (150 random bodies) |
| A13 | Fake deal history | both parties sign one canonical record; both must be registered and not revoked; one-time ids; ±1 h window; stake-at-submission recorded | `test_deals.py` |
| A14 | Fake or double disputes and verdicts | claimant must be a deal party and sign; one case per (deal, claimant); verdicts signed by the arbiter key; one verdict per case; on-chain case id single-use | `test_disputes.py`, testnet slash |
| A15 | Service abuse (floods, oversized bodies) | per-IP rate limit, 16 KB body cap, strict base64url | `test_service.py` |
| A16 | Crash the API with malformed input (wrong types, huge numbers, bad base64url, control characters, lone surrogates, NaN, deep nesting) | every error is 4xx JSON `{"detail": …}`; validation errors never echo the input; path case ids bounded to 0..2^63-1 | `test_api_fuzz.py` (seeded, every endpoint, stores unchanged) |
| A17 | Bypass the body cap with chunked transfer or a malformed Content-Length | body counted while read when there is no usable Content-Length | `test_api_fuzz.py::test_chunked_body_over_the_cap_is_413`, `test_bad_content_length_header` |
| A18 | Restart to reset one-time rules (reuse a challenge, a deal id, a credential slot, a second verdict) | all four stores are SQLite files; challenges live in the registry file | `test_restart.py` |
| A19 | Use a retry to get a second credential, or lose the only credential to a dropped connection | the issuer answers again only for the identical blinded request (SHA-256 digest stored with the pseudonym; same request, same signature); the page saves the request before sending and refuses to send if it cannot save | `test_issuer.py` (retry, other request refused, restart, race, old database), `test_webapp_flow.py::test_lost_answer_is_recovered_by_asking_again`, `test_webapp_page.py::test_lost_answer_is_finished_after_reopening` |
| A20 | Make the holder page leak or accept a wrong answer (other origins, injected script, forged blind signature, swapped issuer key) | page talks to its own origin only (Content-Security-Policy, no inline code, no eval); issuer key id recomputed in the page; unblinded signature checked twice (own arithmetic and WebCrypto PSS) before it is shown | `test_webapp_page.py` (no foreign requests, policy), `test_webapp_crypto.py::test_finalize_refuses_wrong_answers` |
| A21 | Serve arbitrary files through `/app/` | fixed list of file names, no path joining of user input beyond that list | `test_webapp_flow.py::test_webapp_files_are_served_with_safe_headers` |

## Residual risks (accepted for the pilot, to be addressed before mainnet)

- **Trusted issuer (path A).** The issuer can refuse service or, if its pseudonym key leaks together with a
  holder's blinding secret, help link an account. Path B (ZK proof of Telegram's signature) removes it.
- **Arbiter key.** Full slashing power; must be a multisig with published policy. Admin can replace it only
  after the delay.
- **Storage fees.** The contract pays storage from its balance; `get_totals().surplus` must stay positive and
  the admin must top it up. Measured: ≈0.0008 GRAM per record per year, covered by deposit gas dust for about
  a year each.
- **Dust in bounces.** A bounced payout smaller than the gas of the bounce handler stays on the balance
  uncredited (nanogram-scale amounts only).
- **Deal amounts are claims**, not verified transfers; bots should weigh deals with staked counterparties.
- **In memory only:** the rate limiter and the stake cache are lost on restart. A restart resets the one-minute
  windows, so a flood can resume at once; no one-time rule depends on them (`test_restart.py`).
- **Payout address is not signed** by the claimant in a dispute case; whoever can replay a valid case body first
  could set it. Not changed in this release (it would change the signed bytes).
- **The fuzz is in-process.** It does not cover uvicorn or a reverse proxy in front of it, and it checks that
  errors are 4xx, not that every message is useful.
- **Real Telegram data is still unchecked.** Signature tests use a stand-in key until the owner runs `docs/REAL_TELEGRAM_CHECK.md`.
- **Timing links issuance and registration** when the holder lets the Mini App register a new agent at once: the
  service sees both requests seconds apart from one address. Stored data still proves nothing; holders who need
  strict anonymity paste their own public key and register later from the agent (`docs/HOLDER_MINI_APP.md`).
- **Agent key in browser storage.** In the "create a key here" way the key stays in the page's storage until the
  holder confirms the file is saved. Browser arithmetic (BigInt) is not constant-time.
- **The Mini App has not run inside a real Telegram client.** Tests replace Telegram's script with a stub.
- **Testnet only.** No mainnet deployment before an external audit and a legal review.
