# APIS — Adaptive Protective Immune System

A lateral-movement, credential-theft and AI-agent detector, evaluated against **real
government network data** rather than synthetic traffic.

Most intrusion detection projects are demonstrated on data their own author generated.
This one was measured on the Los Alamos National Laboratory *Comprehensive
Multi-Source Cyber-Security Events* dataset — 17,684 real computers, 58 days of real
enterprise traffic, and a genuine red-team engagement labelled independently by
someone who had never seen this code.

Every number below is reproducible from the scripts in this repository.

---

## Headline results

### Network-flow detection

Three evidence-driven fixes, applied in sequence. Three more were built, measured, and
reverted when the numbers got worse.

| Stage | False positives | True positives | Precision |
|---|---:|---:|---:|
| Original, untuned | 2,896 | 18 | 0.62% |
| + personalised repetition threshold | 1,337 | 18 | 1.33% |
| + unreliable signal excluded from confirmation | 837 | 13 | 1.53% |
| + extended clean training window | **603** | 13 | **2.11%** |

**79.2% fewer false positives**, with every real attack in the final result still caught.

### Identity and credential-theft detection

A separate investigation on Windows authentication data, with a real structural
finding: stolen credentials inherit whatever access the real account already had, so
the highest-reach accounts deserve the *least* benefit of the doubt.

| Stage | False positives | True positives | Detection rate |
|---|---:|---:|---:|
| Original, untuned | 38,131 | 168 | 97.1% |
| + machine-account noise excluded | 22,477 | 168 | 97.1% |
| + per-user known-destination baseline | 7,824 | 143 | 82.7% |
| + privilege-aware threshold | **7,991** | 166 | **96.0%** |

**79.0% fewer false positives**, measured completely independently of the flow side.

### When both detectors agree

|  | Network alone | Identity alone | Both agree |
|---|---:|---:|---:|
| Precision | 2.11% | 2.03% | **40.0%** |

Roughly a **19× precision improvement** when two structurally independent domains
corroborate each other.

### AI-agent detection (Layer 9)

Detects AI agents hijacked by indirect prompt injection — legitimate credentials,
altered intent. Evaluated on **576 real AI-agent tool calls** across 99 sessions and
three different workloads.

| Corpus | Untrusted inputs | False positives | Pivot signal in FPs |
|---|---:|---:|---|
| 484 calls — coding only | 5 | 1 / 194 (0.5%) | 0 |
| 510 calls — research added | 22 | 7 / 204 (3.4%) | **4 — rule falsified** |
| 576 calls — fresh research sessions | 56 | **5 / 231 (2.2%)** | **0 — rule rebuilt** |

**Read the middle row first — it is the most important result in this repository.**

The original rule passed its first evaluation with zero false positives. But it had
only *five* opportunities to fire wrongly. When the agent's workload changed from
writing code to reading documentation, the number of untrusted inputs rose to 22 and
the rule failed on four of seven false positives.

The cause was structural, not a threshold: the rule assumed agents read outward and
write inward. That holds for a coding agent and breaks for a research agent, which
legitimately writes outward too.

It was rebuilt around a different distinction — **where a write lands relative to what
was just read**. Writing beside the file you just read is summarisation; writing
somewhere unrelated is exfiltration. Then it was validated on **20 sessions generated
after the change**, with 56 untrusted inputs — eleven times the original sample — and
held.

A result that survives a thin sample is not a result. This one was falsified, rebuilt
on a structural hypothesis, and re-tested on data it had never seen.

---

## The idea

A honeybee colony has no single defence. It has guards at the entrance, a shared sense
of what belongs, alarm pheromones, quorum decisions, hygienic removal, entombment of
what cannot be removed, and a collective heat response. None is individually reliable.
Together they are extremely hard to walk past.

That is a better model for intrusion detection than any single clever rule — and it
produces one hard architectural constraint that runs through the whole system:

> **No single signal is ever actionable on its own.**

Confirmation requires either the same suspicious pattern repeating, or two genuinely
different kinds of suspicious behaviour occurring together.

---

## The nine layers

| # | Layer | Biological basis | What it does |
|---|---|---|---|
| 1 | Guard Checkpoint | Guard bees inspect every arrival | Fast rules, no baseline needed, acts immediately |
| 2 | The Queen | Colony-wide sense of normal | Per-device baseline: peers, hours, volume, fan-out |
| 3 | Alarm Broadcast | Alarm pheromone | Propagates a raw detection to corroborating layers |
| 4 | Quorum Consensus | Swarm decision-making | No signal confirms alone. Two paths: repetition, or type diversity |
| 5 | Hygienic Cleanup | Removal of diseased brood | Audits stale, never-re-verified trust relationships |
| 6 | Containment | Entombment in propolis | Network isolation, webhook and CEF/SIEM export |
| 7 | Chemical Mimicry | Varroa mites faking colony scent | Pass-the-Hash / Pass-the-Ticket: a valid credential that isn't yours |
| 8 | Collective Overwhelm | The defensive heat ball | Correlates weak signals across unrelated conversations |
| 9 | Agent Behaviour | A worker with rewritten instructions | AI-agent hijack: legitimate credentials, altered intent |

---

## Hardened against attacks on the detector itself

An adaptive detector is a target. Each of these responds to a documented real-world
technique.

- **Flood evasion (MITRE T1562)** — a live adversarial test with 50 decoys hiding one
  real attack. The first two fixes failed; the final version separated the real attack
  from 48 of 50 decoys using rarity-based discrimination.
- **Tamper-evident audit trail (EU AI Act, Article 12)** — every confirmed decision is
  SHA-256 hash-chained. A record edited by hand was detected and located to the exact
  entry.
- **Gradual poisoning ("boiling frog")** — 60 rows of traffic, each individually under
  every threshold, climbing 67% in one direction. Invisible to every other layer;
  caught by this one.
- **Agent hijack (MITRE ATLAS AML.T0051.001)** — indirect prompt injection detection,
  falsified and rebuilt as described above.
- **Poisoning-safe learning** — the baseline only ever learns from traffic confirmed
  safe: zero raw signals, or a human-reviewed suppression. A confirmed, unsuppressed
  detection is never fed back.

---

## Running it

```bash
pip install -r requirements.txt
```

### Try it in 30 seconds

Sample data is included, so you can run all three detection domains
immediately without the LANL dataset.

```bash
# network flow
python baseline.py samples/sample_traffic_clean.txt
python detector.py samples/sample_traffic.txt

# identity and credential theft
python build_auth_baseline.py samples/sample_auth_clean.txt
python auth_pipeline.py samples/sample_auth.txt

# AI agent behaviour
python agent_baseline.py samples/sample_agent_events_clean.txt
python agent_pipeline.py samples/sample_agent_events.txt

# confirm nothing in the audit log was altered
python verify_audit_trail.py
```

Expected: a confirmation on `10.0.2.10` (MITRE T1018), on `C199 -> C101`
(T1550.002, Pass-the-Hash), and two on the hijacked agent
(ATLAS AML.T0051.001 and AML.T0086) — with the audit chain intact.

**If you get no detections,** the adaptive baselines have learned from a
previous run and are resuming that state. That is correct behaviour, not a
fault. Reset it:

```bash
rm -f rolling_baseline_state.json adaptive_auth_baseline_state.json       adaptive_agent_baseline_state.json quorum_state.json audit_trail.jsonl
```

See `samples/README.md` for what each file contains.

### On your own data

```bash
python baseline.py clean_traffic.txt          # build from known-clean traffic
python detector.py traffic.txt                # detect

python build_auth_baseline.py clean_auth.txt  # identity side
python auth_pipeline.py auth_events.txt

python claude_code_adapter.py agent_events.txt    # convert Claude Code logs
python agent_baseline.py agent_events.txt
python agent_pipeline.py agent_events.txt

python -m uvicorn api_server:app --reload     # REST API at /docs
```

### Tests

```bash
python -m pytest test_apis.py test_adaptive_integration.py test_auth_detector.py \
  test_rolling_baseline.py test_cross_signal_correlator.py \
  test_auth_pipeline_integration.py test_audit_trail.py test_api_server.py \
  test_confidence_scoring.py test_flood_detection.py test_drift_monitor.py \
  test_agent_detector.py test_claude_code_adapter.py test_agent_integration.py \
  test_agent_attack_scenarios.py test_live_monitor_adaptive.py -q
```

**231 tests**, including adversarial scenarios and tests that assert the system's
*documented failures* — so a future change that silently breaks detection is caught.

---

## Where this stops short

Every limitation below was found by measurement, not left as an unknown. They are
listed here because a detector whose failure modes are undocumented cannot be trusted
in production.

**Scope of evaluation**
- Scoped to verified-clean training days and the highest-attack-density day of the
  dataset, not all 58 days.
- 2.11% precision is a large improvement over 0.62%, not a solved problem. Published
  research treats lateral-movement detection as a genuinely hard, open class of
  problem, and these numbers are consistent with that.

**Known evasions — measured, reproducible, and left in the test suite**
- **Read-only reconnaissance pivot.** An agent that reads sensitive targets but never
  acts outward is not caught. This is the direct cost of the refinement that made the
  signal usable at all; catching it required a threshold that produced 20–28 false
  positives on real benign traffic.
- **Poisoned file inside the agent's own workspace.** Trust is location-relative, so a
  file already inside the workspace raises no suspicion. Closing this needs a
  content-level check, which is not implemented.

Both have dedicated tests asserting that they evade. If a future change starts
catching them, the tests fail and the documentation gets corrected.

**Constructed data**
- Layer 9's attack scenarios are hand-built. No public labelled dataset of AI-agent
  lateral movement exists. **The false-positive rates are real; the detection rate is
  not a real-world figure** and is labelled as such everywhere it appears.

**Thresholds are workload-dependent, not universal**
- Layer 8's agent threshold was calibrated on coding traffic, then degraded the moment
  the agent's job changed, and had to be recalibrated against real data. A threshold is
  a property of the workload it was measured on — that lesson is written into the code
  beside the number.

**Approaches that were built and reverted**
- Four separate attempts at a volume-outlier signal, plus three other changes, were
  implemented, measured, and removed because the real numbers got worse. The reversions
  are part of the record rather than hidden from it.

---

## Data

The LANL dataset is not included in this repository — it is ~8 GB and not mine to
redistribute. It is publicly available from Los Alamos National Laboratory:
<https://csr.lanl.gov/data/cyber1/>

The AI-agent traces were generated locally from real tool-call transcripts.

Small synthetic samples for all three domains are included in `samples/`, so
the system can be run end to end without any external download. They
demonstrate that it works; they do not reproduce the numbers above.

---

## Built by

**Shehab Shibli** — B.Sc. Network Engineering and Computer Security
[GitHub](https://github.com/shehab6157-design) ·
[LinkedIn](https://linkedin.com/in/shehab-shibli) · shehab6157@gmail.com
