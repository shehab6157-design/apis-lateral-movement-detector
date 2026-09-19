# notify.py — Alert Delivery Notes

## What it does
`notify.py` sends alerts out via a generic webhook rather than a Slack-specific SDK. Since Slack's
"incoming webhook" feature is just an HTTP POST of a JSON body to a URL, this same code path already
delivers real Slack alerts as soon as a Slack webhook URL is set in `config.json` — no extra
dependency required.

## How it works
- **Entry point:** `send_webhook_alert(message, webhook_url=None)`
- **Webhook URL resolution:** uses the `webhook_url` argument if provided, otherwise falls back to
  `CONFIG["notifications"]["webhook_url"]` (from `config.py`'s `CONFIG`).
- **No-op safety:** if no webhook URL is configured, the function returns
  `(False, "no webhook configured - alert stayed console-only")` and does nothing else. It never
  replaces existing console output elsewhere in the project.
- **Payload:** builds `{"text": message}`, JSON-encodes it, and POSTs it to the webhook URL using
  `urllib.request` with header `Content-Type: application/json`.
- **Request handling:** uses a 5-second timeout.
  - On success, returns `(True/False, "delivered (HTTP <status>)")` — success is `200 <= status < 300`.
  - On `urllib.error.URLError`, returns `(False, "delivery failed: <error>")`.
  - On any other exception, returns `(False, "delivery failed (unexpected): <error>")`.
- **CLI usage:** running `python notify.py <message...>` sends the joined args (or a default
  `"APIS test alert"` message) and prints `Success: <ok> | <detail>`.

## Key takeaway
Alert delivery is entirely opt-in and config-driven: without a `webhook_url` in `config.json`,
alerts stay console-only; with one configured (Slack or otherwise), this module posts them as a
plain JSON webhook call.
