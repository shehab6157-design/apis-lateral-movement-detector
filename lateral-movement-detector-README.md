# Lateral Movement Detector

Detects "east-west" internal network traffic anomalies — the pattern
an attacker leaves behind while moving between already-compromised
internal hosts using legitimate protocols (SMB, RDP, SSH). Signature-
and perimeter-based tools miss this by design: they watch traffic
crossing the network boundary, not traffic between machines that are
already inside.

## Approach

No ML black box — a behavioral baseline per device, built from
descriptive statistics, so every alert can be explained in plain
terms ("this host normally talks to 3 peers; right now it's
contacting 8, at 2 AM, with 20x its usual transfer size").

For each device, the baseline learns:
- **known peers** — which internal hosts it normally talks to
- **active hours** — when it's normally active
- **typical transfer size** — mean/std bytes per flow
- **typical fan-out** — mean/std of distinct peers contacted per hour

New traffic is compared against this baseline and flagged on 4
independent signals:

| Signal | Meaning |
|---|---|
| `NEW_PEER` | talking to an internal host never seen before |
| `OFF_HOURS` | active outside its normal hours |
| `VOLUME_OUTLIER` | a flow's size is a statistical outlier (z-score) |
| `FANOUT_SPIKE` | contacting far more distinct peers in one hour than usual |

A single signal alone can be noise. Multiple signals firing together
on the same flow is what makes an alert worth acting on — which is
exactly what the simulated attack triggers (all 4 at once).

## Files

| File | Purpose |
|---|---|
| `simulate.py` | Generates synthetic normal traffic for 6 devices over 5 days, plus a separate test file with a simulated lateral-movement attack injected |
| `baseline.py` | Learns the per-device baseline from a traffic CSV → `baseline.json` |
| `detector.py` | Compares new traffic against `baseline.json`, flags the 4 anomaly types |
| `capture.py` | Converts a real `.pcap` capture into the same CSV format, so real traffic can be tested the same way as synthetic data |

## Testing on synthetic data

```bash
python3 simulate.py            # writes traffic.csv (normal-only) + test_traffic.csv (normal + attack)
python3 baseline.py traffic.csv    # learns baseline.json from normal-only traffic
python3 detector.py test_traffic.csv   # tests against the file that includes the attack
```

Result: **5/5 attack flows flagged, 0 false positives** on the
normal traffic. The very first attack flow triggers all 4 signals
simultaneously (new peer + off-hours + oversized transfer + fan-out
spike) since the simulated compromised host contacts 5 new internal
targets within 12 minutes, at 2 AM, pulling unusually large transfers.

### A real bug found and fixed during testing

The first version of `baseline.py` computed fan-out standard
deviation directly from the data with no floor. On a small internal
network, a device's normal fan-out is often just 1-2 peers/hour,
which makes that std tiny (0.2-0.4) — and a tiny std turns a
completely ordinary +1 peer in one hour into an exploding z-score.
Re-running the pure normal-only traffic through the detector (before
any attack was involved) showed a max fan-out z-score of **5.0** —
higher than the attack's own signal — which meant the detector would
have flagged normal daily variation constantly.

Fix: floor `std_fanout_per_hour` at 1.0. Re-checked: max normal
z-score dropped to 1.9 (under the 2.0 threshold), and the real attack
still scored well above it (z ≈ 5.2). This is exactly the kind of
gap that only shows up by testing the detector against its own
"normal" data, not just the attack case — worth mentioning as-is in
an interview.

## Testing on real captured traffic

Real traffic was captured from a 3-node VirtualBox internal network
(SEED Ubuntu VMs on an isolated `intnet`), using:

```bash
sudo tcpdump -i enp0s3 -w normal_traffic.pcap &
# generate real traffic between the VMs (ping, ssh, etc.)
sudo pkill tcpdump
```

Then converted with:

```bash
python3 capture.py normal_traffic.pcap --output real_traffic.csv
```

`capture.py` maps each captured packet to the same
`timestamp, src_ip, dst_ip, dst_port, protocol, bytes` schema
`simulate.py` produces, so `baseline.py` and `detector.py` work on it
unmodified.

**Caveat:** a few minutes of ping traffic between 3 VMs is nowhere
near enough data to build a statistically meaningful baseline on its
own (not enough distinct hours, not enough flow-size variety). It's
a real-data sanity check that the pcap→CSV conversion pipeline works
end-to-end — the next step is capturing across longer, more varied
sessions (multiple days, more protocols: SSH, SMB/file shares, not
just ICMP) before the real capture can replace the synthetic baseline
for a genuine test.

## Not yet done

- Longer, more varied real-traffic capture sessions (multiple days,
  multiple protocols) to build a real baseline instead of a synthetic one
- Testing the detector against a real simulated attack replayed on
  the VM network (e.g. one VM suddenly SSHing/SMB-connecting to
  several others it's never touched)
- Tuning thresholds (`VOLUME_ZSCORE_THRESHOLD`, `FANOUT_ZSCORE_THRESHOLD`)
  against real traffic's natural variance, which will likely differ
  from the synthetic data's
