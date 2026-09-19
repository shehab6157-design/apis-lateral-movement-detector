"""
contain.py — Layer 6 of the APIS project (Adaptive Protective Immune System)

Biological basis: entombment - contain a threat you can't safely
destroy, rather than trying to eliminate it outright.

Separates REPORTING from ENFORCEMENT: a SOC wants SIEM/webhook
visibility into every confirmed detection regardless of whether
autonomous containment is turned on - report_confirmed_pair() always
runs. The actual destructive action (real Docker network isolation)
only ever runs under --enforce, via handle_confirmed_pair().
"""

import subprocess
import sys

from notify import send_webhook_alert
from siem_export import to_cef, send_syslog_cef
from config import CONFIG

NETWORK_NAME = "labnet"


def find_container_by_ip(ip):
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", NETWORK_NAME, "-f",
             "{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}"],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"  [CONTAIN] Could not inspect network '{NETWORK_NAME}': {e.stderr.strip()}")
        return None
    except FileNotFoundError:
        print("  [CONTAIN] 'docker' command not found - is Docker installed and on PATH?")
        return None

    for pair in result.stdout.split():
        if "=" not in pair:
            continue
        name, addr = pair.split("=", 1)
        addr_ip = addr.split("/")[0]
        if addr_ip == ip:
            return name
    return None


def isolate_container(ip, reason):
    container = find_container_by_ip(ip)
    if container is None:
        print(f"  [CONTAIN] No container found for IP {ip} on '{NETWORK_NAME}' - no action taken.")
        return False

    print(f"  [CONTAIN] Isolating '{container}' ({ip}) from '{NETWORK_NAME}'. Reason: {reason}")
    try:
        subprocess.run(
            ["docker", "network", "disconnect", "--force", NETWORK_NAME, container],
            capture_output=True, text=True, check=True,
        )
        print(f"  [CONTAIN] '{container}' disconnected successfully - it is now isolated.")
        ok, detail = send_webhook_alert(f":rotating_light: APIS isolated '{container}' ({ip}). Reason: {reason}")
        print(f"  [NOTIFY] {detail}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [CONTAIN] FAILED to disconnect '{container}': {e.stderr.strip()}")
        return False


def report_confirmed_pair(src, dst, summary, path, action):
    cef_message = to_cef(src, dst, summary, path, action)
    print(f"  [SIEM/CEF] {cef_message}")

    syslog_host = CONFIG.get("siem", {}).get("syslog_host")
    if syslog_host:
        ok, detail = send_syslog_cef(
            cef_message,
            host=syslog_host,
            port=CONFIG["siem"].get("syslog_port", 514),
            use_tcp=CONFIG["siem"].get("syslog_tcp", False),
        )
        print(f"  [SIEM/SYSLOG] {detail}")

    if action != "AUTONOMOUS_ACTION_OK":
        ok, detail = send_webhook_alert(f":warning: APIS flagged {src} -> {dst} for human review: {summary}")
        print(f"  [NOTIFY] {detail}")


def handle_confirmed_pair(src, dst, summary, action):
    if action == "AUTONOMOUS_ACTION_OK":
        isolate_container(src, reason=f"quorum confirmed with sufficient independent evidence: {summary}")
    else:
        print(f"  [CONTAIN] {src} -> {dst} - ESCALATED FOR HUMAN REVIEW. No automatic action taken.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Standalone test usage: python3 contain.py <ip-to-isolate>")
        sys.exit(1)
    isolate_container(sys.argv[1], reason="manual test")
