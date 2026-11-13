# Check a real Telegram signature (about five minutes)

Until this is done, every signature test in this repository uses a local stand-in key. This check runs
`tgtrust/telegram_sig.py` on a string that Telegram itself signed, with Telegram's published public key.
Nothing here is hosted or sent by this repository; you do the steps.

## Steps

1. **Bot.** In [@BotFather](https://t.me/BotFather) create a bot (`/newbot`) or reuse one. Note its numeric id:
   it is the part of the bot token before the colon. Treat the token itself as a secret; it is not needed below.
2. **Host the page.** Put `miniapp/index.html` on any HTTPS address you control (static hosting is enough). The
   page makes no requests and stores nothing; its only external script is `https://telegram.org/js/telegram-web-app.js`.
3. **Set the Mini App URL.** In BotFather: `/mybots` → your bot → Bot Settings → Menu Button → set the URL of
   the hosted page (or `/newapp` and use the Main Mini App link).
4. **Open it** inside Telegram from the bot's menu button. The page shows "Init data present: yes", its length
   and `auth_date`. Opened in a normal browser it says it is not inside Telegram.
5. **Copy.** Tap "Copy init data".
6. **Save to a file.** Paste into a file, for example `init.txt` (a file, not the command line, so the string
   does not land in shell history). Work quickly: the default freshness window is 900 seconds.
7. **Run** (production Telegram; add `--env test` for the Telegram test environment):

   ```
   python -m tgtrust.telegram_sig --init-data-file init.txt --bot-id 1234567890
   ```

   Optional: `--max-age SECONDS` changes the freshness window.
8. Delete `init.txt`. It contains your Telegram user data until it expires.

## Output

One line, exit code 0 or 1, never your user id, name or the raw string:

- `VALID: user id present, auth_date 2026-11-12T03:00:00Z, age 42 s`
- `INVALID: <exact reason>`, for example `signature does not match` (wrong bot id, wrong environment, or
  altered data), `init data has expired`, `signature field is missing`.

If you get `signature does not match`, try the other `--env` and check the bot id first.

## What VALID proves

- Telegram's Ed25519 key for that environment signed exactly this string for exactly this bot id.
- The data is fresh (within `--max-age`) and has a numeric user id.
- The verification code that the issuer uses works on a real Telegram signature, not only on the stand-in key.

## What VALID does not prove

- Not that the Telegram account belongs to a real person, or who they are. The issuer checks one credential per
  Telegram account per issuer epoch; owner identity is not checked.
- Not that the issuer service, the registry or the stake contract work with this data; it checks only the signature.
- Not that the bot id you passed is a bot you own: it proves the string was made for that bot id.
- One run proves one string. Record the date and the environment (`production` or `test`) if you cite it.

## Record

- 2026-11-12, `production`: init data from a live Mini App returned `VALID`. The same string checked with a
  wrong bot id, and with the user field altered, returned `INVALID: signature does not match`. The init data
  was deleted after the check and is not stored anywhere.
