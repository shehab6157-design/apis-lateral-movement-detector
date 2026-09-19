"""
notify.py — real alert delivery via webhook (layer 6/enforcement support).

A webhook is deliberately the target here rather than a Slack-specific
or email-specific integration: Slack's own "incoming webhook" feature
IS just an HTTP POST of a JSON body to a URL - so this module already
delivers real Slack alerts the moment a real Slack webhook URL is put
in config.json, with no SDK or extra dependency needed.

If no webhook_url is configured, this is a safe no-op - it does NOT
replace any existing console output anywhere in this project.
"""

import json
import urllib.request
import urllib.error

from config import CONFIG


def send_webhook_alert(message, webhook_url=None):
    webhook_url = webhook_url or CONFIG.get("notifications", {}).get("webhook_url")
    if not webhook_url:
        return False, "no webhook configured - alert stayed console-only"

    payload = json.dumps({"text": message}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return (200 <= resp.status < 300), f"delivered (HTTP {resp.status})"
    except urllib.error.URLError as e:
        return False, f"delivery failed: {e}"
    except Exception as e:
        return False, f"delivery failed (unexpected): {e}"


if __name__ == "__main__":
    import sys
    msg = " ".join(sys.argv[1:]) or "APIS test alert"
    ok, detail = send_webhook_alert(msg)
    print(f"Success: {ok} | {detail}")
