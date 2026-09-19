"""
siem_export.py — exports confirmed detections in CEF (Common Event
Format), the ArcSight-originated but now near-universal SIEM ingestion
format supported natively by Splunk, Microsoft Sentinel, IBM QRadar,
and Elastic. Real security teams don't adopt a new standalone tool -
they want alerts flowing into what they already run.

Format verified against the current ArcSight CEF specification:
    CEF:Version|Device Vendor|Device Product|Device Version|
    Device Event Class ID|Name|Severity|Extension
"""

import socket
from datetime import datetime

from mitre_mapping import annotate_summary_with_attack

CEF_VERSION = 0
DEVICE_VENDOR = "APIS"
DEVICE_PRODUCT = "LateralMovementDetector"
DEVICE_VERSION = "1.0"

SEVERITY_MAP = {
    "AUTONOMOUS_ACTION_OK": 9,
    "ESCALATE_FOR_REVIEW": 6,
}


def _cef_escape_header(value):
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_extension(value):
    return str(value).replace("\\", "\\\\").replace("=", "\\=")


def to_cef(src, dst, summary, path, action):
    technique_ids = annotate_summary_with_attack(summary)
    technique_str = ",".join(technique_ids) if technique_ids else "none"

    signature_id = technique_ids[0] if technique_ids else "APIS-GENERIC"
    name = f"Lateral movement signals: {', '.join(sorted(summary.keys()))}"
    severity = SEVERITY_MAP.get(action, 5)

    extension_parts = [
        f"src={_cef_escape_extension(src)}",
        f"dst={_cef_escape_extension(dst)}",
        f"cat={_cef_escape_extension(path)}",
        f"act={_cef_escape_extension(action)}",
        "cs1Label=MITRE_ATTACK_TECHNIQUES",
        f"cs1={_cef_escape_extension(technique_str)}",
        f"cnt={sum(summary.values())}",
    ]

    header = "|".join([
        f"CEF:{CEF_VERSION}",
        _cef_escape_header(DEVICE_VENDOR),
        _cef_escape_header(DEVICE_PRODUCT),
        _cef_escape_header(DEVICE_VERSION),
        _cef_escape_header(signature_id),
        _cef_escape_header(name),
        str(severity),
    ])

    return f"{header}|{' '.join(extension_parts)}"


def send_syslog_cef(cef_message, host="localhost", port=514, use_tcp=False):
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = socket.gethostname()
    full_message = f"{timestamp} {hostname} {cef_message}"

    try:
        if use_tcp:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((host, port))
                sock.sendall((full_message + "\n").encode("utf-8"))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(full_message.encode("utf-8"), (host, port))
        return True, f"sent to {host}:{port} ({'TCP' if use_tcp else 'UDP'})"
    except OSError as e:
        return False, f"failed to send: {e}"


if __name__ == "__main__":
    example_cef = to_cef("10.0.2.10", "10.0.2.11", {"NEW_PEER": 1, "FANOUT_SPIKE": 1},
                          "type_diversity", "AUTONOMOUS_ACTION_OK")
    print("Example CEF message:")
    print(example_cef)
