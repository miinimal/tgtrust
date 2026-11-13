# Holder Mini App: getting a credential without writing code

The issuer service serves a page at `/app/` (files in `tgtrust/webapp/`). Opened as a Telegram Mini App, it
takes an agent owner from "I have a Telegram account" to "my agent holds a credential" in one screen. The
blind-signature mathematics runs in the browser, in the page's own code; the issuer never sees the credential.

## What the holder does

1. Opens the Mini App from the issuer's bot.
2. Chooses one of two ways:
   - **My agent already has a key** (safest). On the agent's machine: `python -m tgtrust.client new-key --out agent.key`
     prints the public key. The holder pastes it into the page. The page returns `credential.json`. On the agent's
     machine: `python -m tgtrust.client register --credential credential.json --key-file agent.key`.
   - **Create a key for a new agent here** (quickest). The page creates the key, obtains the credential, registers
     the agent and shows `agent.json` (key and credential together). The agent loads it with
     `tgtrust.client.AgentIdentity.from_agent_file("agent.json")`.
3. Saves the file and presses "I saved it. Remove it from this device".

## What travels where

| Value | Leaves the device? | To whom |
| --- | --- | --- |
| Telegram init data (signed by Telegram) | yes | issuer, `POST /v1/issue` |
| Blinded request | yes | issuer, `POST /v1/issue` |
| Blinding secret | no | |
| Agent private key (second way only) | no | |
| Finished credential and agent public key | only in the second way | issuer, `POST /v1/register` |

The page talks to its own origin only. Its Content-Security-Policy forbids every other destination, inline code
and `eval`; the single external script is Telegram's `telegram-web-app.js`. Files are served with `no-store`,
`nosniff` and `no-referrer`, by exact name from a fixed list.

## If the connection drops

A Telegram account gets one credential per issuer epoch, so a lost answer must not cost the holder the
credential. Two mechanisms cover it:

- The page saves the request on the device **before** sending it. If the page cannot save, it refuses to send.
- The issuer records a SHA-256 digest of the blinded request next to the account pseudonym. The same account
  may send **the same** request again and receives the same signature (signing is deterministic). Any other
  request from that account is refused with `already_issued`, as before.

On reopening, the page finds the saved request and offers "Finish the request". The saved record holds the
blinding secret only until the signature is verified, and the whole record is removed when the holder confirms
the file is saved.

## Running it

The page needs nothing beyond the service: `uvicorn --factory tgtrust.service:create_app` serves it at
`https://<issuer host>/app/`. In BotFather set that address as the bot's Mini App (Bot Settings → Menu Button, or
`/newapp`). `TGTRUST_BOT_ID` must be the id of that bot, because Telegram signs init data per bot.

## What is tested, and how

- `tests/test_webapp_crypto.py` runs the browser code under Node and compares it byte for byte with
  `tgtrust/blind_rsa.py` and `tgtrust/registry.py`: key parsing, the PSS encoding, blinding with a fixed factor,
  browser blinds → Python signs → browser unblinds → both Python and WebCrypto verify, refusal of wrong answers.
- `tests/test_webapp_flow.py` runs the page's flow code against a live HTTP service: both ways, a lost answer
  recovered by asking again, a second credential refused, every error code, file serving.
- `tests/test_webapp_page.py` drives the real page in Chromium: both ways end to end, the lost-answer recovery
  after reopening, the copy button, English for every user language, light and dark, widths from 320 px, no request to any
  other origin, no console error.
- `tests/test_issuer.py` covers the retry rule in the issuer, including a restart and a concurrent race.
- `tests/test_client_cli.py` covers the agent-side commands and the two file formats.

The Node and browser tests are skipped when Node or Playwright is not installed.

## Not verified

- The page has not been opened inside a real Telegram client; tests replace Telegram's script with a stub that
  supplies init data signed by a stand-in key. See `docs/REAL_TELEGRAM_CHECK.md` for the owner's check of real
  init data; the same bot can host this page.
- No published RFC 9474 test vector is included. Correctness rests on agreement between two independent
  implementations (this code and the Python one) and two independent standard verifiers (`cryptography` and
  WebCrypto).
- Agent keys are created with WebCrypto Ed25519. A browser without it gets the first way only; the page detects
  this and says so.

## Limits to know

- **Timing.** In the second way the page registers the agent seconds after issuance, from the same address. The
  issuer service can guess the link between account and agent from timing. The blind signature still prevents
  proof from stored data, but for strict anonymity use the first way and register later, from the agent.
- **The device.** Until the holder confirms the file is saved, the agent key (second way) sits in the browser's
  storage for this page. Anything that can read that storage can take the agent.
- **Arithmetic is not constant-time.** The browser code uses BigInt. The secret blinding factor is used once,
  on the holder's own device, for a one-time request.
