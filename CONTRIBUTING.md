# Contributing

Issues and pull requests are welcome. Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Set up

```
git clone https://github.com/miinimal/tgtrust && cd tgtrust
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,browser]" && playwright install chromium
pytest                                  # Python suite, nothing may be skipped
cd contracts && npm ci && npm test      # contract sandbox tests (Node 22)
```

## Rules

- Every change comes with a test; a bug fix comes with the test that failed before it.
- CI (`checks`) runs the Python suite with Node and Chromium, the contract tests and the Docker image build.
  It fails on any skipped test.
- Keep secrets out of the repository: issuer keys, pseudonym keys, bot tokens and mnemonics come from
  environment variables only (see `deploy/env.example`).
- Code, comments and docs in English. Claims in docs must match what the code proves: a credential means one
  Telegram account per issuer epoch, not one person.
- Changes to the cryptographic design (token format, signature scheme, contract storage) need an issue first.
