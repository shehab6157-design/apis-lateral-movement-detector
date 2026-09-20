# Lateral Movement Detector — Baseline & Anomaly Prototype

A small, honest first version of the lateral-movement / east-west visibility
problem: instead of matching known-bad signatures, this learns what "normal"
internal traffic looks like for each device on a network, then flags
deviations that match how real lateral movement behaves.

## Why this design

Perimeter tools watch traffic crossing the internet boundary. Once an
attacker is already inside — via phishing, a stolen credential, a
compromised IoT device — they move server-to-server, laptop-to-file-share,
using **legitimate protocols and legitimate credentials**. Nothing here is
"known-bad" on its own; it's normal traffic in a slightly wrong pattern,
destination, or time. That's why signature matching doesn't catch it, and
why the approach here is behavioral instead.

The four things this flags, and why each one matters:

| Alert type       | What it means                                            | Why it maps to lateral movement                  |
|-------------------|-----------------------------------------------------------|---------------------------------------------------|
| `NEW_PEER`        | Device talked to a host it's never talked to before        | Attackers pivot to hosts the compromised device has no business reason to reach |
| `FANOUT_SPIKE`     | Device suddenly reached far more distinct hosts in an hour than usual | The single strongest signature of lateral movement: "scan/hop to many machines quickly" |
| `OFF_HOURS`       | Device active at a time it's historically never active     | Attackers often operate at night/off-hours to reduce chance of being watched |
| `VOLUME_OUTLIER`  | A single connection moved far more data than normal          | Could indicate staging/exfiltration of data from an internal host |

Each alert prints **why** it fired in plain language — deliberately, since
alert fatigue (too many unexplained alerts) is itself a widely acknowledged
problem in this space. A tool that can't explain itself just adds noise.

## Files

- `simulate.py` — generates synthetic "normal" internal traffic plus a test
  day with an injected lateral-movement pattern, so you can test the whole
  pipeline before you have real captured traffic.
- `baseline.py` — reads a CSV of traffic and learns, per device: its normal
  peers, active hours, typical connection size, and typical fan-out per hour.
- `detector.py` — compares new traffic against the baseline and raises
  alerts with explanations.
- `capture.py` — converts a real `.pcap` file (or a live capture, via
  `tshark`) into the same CSV format, so you can point this at a real test
  network once you're ready.

## Quick start (synthetic data, no setup needed)

```bash
python3 simulate.py     # creates traffic_baseline_period.csv and traffic_test_day_with_attack.csv
python3 baseline.py     # learns normal behavior -> baseline.json
python3 detector.py     # flags the injected attack in the test day
```

## Moving to a real test network

1. Set up a few VMs or devices you control (a "workstation", a small file
   share, an auth server — even 3-4 machines is enough to start).
2. Capture a few days of *normal* use with Wireshark/tcpdump, or:
   ```bash
   sudo python3 capture.py --live eth0 --duration 3600 --out traffic_real.csv
   ```
3. Run `baseline.py` against that real CSV to build a real baseline.
4. Simulate an attack pattern yourself (e.g. RDP from one VM into several
   others back-to-back) and capture that traffic separately.
5. Run `detector.py` against the attack-day traffic and see what fires.

## Honest limitations (worth naming out loud, including in an interview)

- Thresholds (`FANOUT_SIGMA_THRESHOLD`, `VOLUME_SIGMA_THRESHOLD`) are
  reasonable starting guesses, not tuned against real false-positive data —
  a real deployment would calibrate these against weeks of real traffic.
- The baseline currently has no concept of "this device just got a new
  legitimate job function" (e.g. someone joins a new project and
  legitimately starts talking to a new server) — it would need periodic
  re-baselining or a decay/aging mechanism to stay useful long-term.
- This treats each device independently; real lateral movement often
  involves a chain across multiple hosts (A -> B -> C), which a more
  advanced version would need to correlate across devices, not just per-host.
- No ML model here on purpose — the per-device statistics are simple and
  fully explainable, which is a deliberate tradeoff against the "black box
  flags things nobody can explain" failure mode that makes alert fatigue worse.
