"""
capture.py
------------
Converts a real .pcap file into the same CSV format simulate.py
produces, plus one new field: ssh_banner, extracted from the cleartext
SSH version-exchange packet when present (RFC 4253 - both sides send
their client/server software identifier in the clear before encryption
begins, so this needs no decryption).
"""

import argparse
import csv
from datetime import datetime, timezone

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP


def protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return str(packet[IP].proto) if packet.haslayer(IP) else "UNKNOWN"


def dest_port(packet):
    if packet.haslayer(TCP):
        return packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].dport
    return 0


def ssh_banner(packet):
    if not packet.haslayer("Raw"):
        return None
    payload = bytes(packet["Raw"].load)
    if payload.startswith(b"SSH-"):
        try:
            return payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
        except Exception:
            return None
    return None


def pcap_to_rows(pcap_path):
    packets = rdpcap(pcap_path)
    rows = []
    skipped = 0

    for packet in packets:
        if not packet.haslayer(IP):
            skipped += 1
            continue

        ts = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).replace(tzinfo=None)
        src = packet[IP].src
        dst = packet[IP].dst
        port = dest_port(packet)
        proto = protocol_name(packet)
        size = len(packet)
        banner = ssh_banner(packet) or ""

        rows.append([ts.isoformat(), src, dst, port, proto, size, banner])

    return rows, skipped


def write_csv(rows, path):
    rows.sort(key=lambda r: r[0])
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "ssh_banner"])
        writer.writerows(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert a .pcap capture into detector-ready CSV.")
    parser.add_argument("pcap_file", help="Path to the .pcap file (e.g. normal_traffic.pcap)")
    parser.add_argument("--output", default="real_traffic.csv",
                         help="Output CSV path (default: real_traffic.csv)")
    args = parser.parse_args()

    print(f"Reading {args.pcap_file}...")
    rows, skipped = pcap_to_rows(args.pcap_file)

    print(f"Converted {len(rows)} IP packets to CSV rows.")
    banner_count = sum(1 for r in rows if r[6])
    print(f"Found SSH banners in {banner_count} of those rows.")
    if skipped:
        print(f"Skipped {skipped} non-IP packets (ARP, etc.) - not relevant to this detector.")

    write_csv(rows, args.output)
    print(f"Saved to {args.output}")
