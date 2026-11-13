# Deploying the tgtrust issuer and badge bot

Target: any Linux server with Docker. The issuer listens on 127.0.0.1:8080 and must sit behind a TLS reverse
proxy (Caddy or nginx) on a public hostname; the bot container talks to the issuer over the compose network.

## One-time setup on the server

```
cd ~ && git clone https://github.com/miinimal/tgtrust.git && cd tgtrust/deploy
cp env.example .env
python3 -c "import os; print(os.urandom(32).hex())"      # paste as TGTRUST_PSEUDONYM_KEY in .env
nano .env                                                  # TGTRUST_BOT_ID, TGTRUST_BOT_TOKEN
docker compose build
docker compose run --rm --entrypoint python issuer -m tgtrust.keys /data/issuer.pem
docker compose up -d
curl -s http://127.0.0.1:8080/v1/health
```

If the key file is missing or wrong, the issuer stops at start with one line, for example
`cannot load issuer key TGTRUST_ISSUER_KEY_FILE=/data/issuer.pem: file not found`.
Create the key with `python -m tgtrust.keys <path>` (the `docker compose run` line above does this for `/data/issuer.pem`).

Settings:

- `TGTRUST_BOT_ID` — numeric id of the Mini App bot whose init data the issuer accepts (the part before the colon
  in the bot token).
- `TGTRUST_BOT_TOKEN` — token of the demo badge bot (may be the same bot).
- `TGTRUST_PSEUDONYM_KEY` — 32 random bytes in hex; changing it later resets the one-credential-per-account rule.
- `TGTRUST_STAKE_CONTRACT` / `TGTRUST_TON_NETWORK` — StakeRegistry deployment the badge reads.
- All four databases (`issuer.db`, `registry.db`, `deals.db`, `disputes.db`) live in the `tgtrust-data` volume under
  `/data`; this volume is what must be backed up.
- `TGTRUST_TRUST_FORWARDED_FOR=1` only when a reverse proxy sets `X-Forwarded-For`.

## Reverse proxy (Caddy example)

```
trust.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

## Update

```
cd ~/tgtrust && git pull && cd deploy && docker compose build && docker compose up -d
```

## Check

- `curl https://trust.example.org/v1/issuer` — issuer key and policy.
- `curl https://trust.example.org/v1/agents/738559c16db0b6b80b73de6094744bd9e802fb7df4657b3f41fdd3c7238228d8/badge`
  — the testnet demo stake (0.4 GRAM, read 2026-11-13) must show `stake.found: true`.
- In Telegram: send `/badge 738559c16db0b6b80b73de6094744bd9e802fb7df4657b3f41fdd3c7238228d8` to the bot.

## Holder Mini App

The service serves the holder page at `/app/` (same origin as the API, no extra hosting). After the service is
reachable over HTTPS, set `https://<your host>/app/` as the Mini App of the bot whose id is in `TGTRUST_BOT_ID`
(BotFather → Bot Settings → Menu Button). What the page does and its limits: `docs/HOLDER_MINI_APP.md`.
