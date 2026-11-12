# Security policy

tgtrust is a reference implementation on TON **testnet**. It has not had an external audit; do not lock real
funds with it.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository
(private vulnerability reporting). Do not open a public issue for anything that could be abused before a fix.

Include what you can: the affected part (Telegram signature check, blind signatures, issuer, registry, HTTP
service, Mini App, `StakeRegistry` contract), steps or a test that shows the problem, and the impact you see.
You will get an answer within a few days. Reports about the cryptographic design are as welcome as code bugs.

## Scope and known limits

The threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Known limits of this version:

- The issuer is a single trusted party (path A): it can refuse service or issue extra credentials; it cannot
  link a credential to a Telegram account.
- The arbiter key can slash stakes; in production it must be a multisig.
- Signatures over real Telegram init data have been checked only with a stand-in key so far
  (see [docs/REAL_TELEGRAM_CHECK.md](docs/REAL_TELEGRAM_CHECK.md)).
- The HTTP rate limit is per process and in memory; run one issuer process behind a TLS reverse proxy and set
  `TGTRUST_TRUST_FORWARDED_FOR=1` only when that proxy appends the client address.
- The Mini App's Content Security Policy is set in the page; a hosting proxy should also send it as a header.
