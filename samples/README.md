# Sample data

Small synthetic files so you can run APIS end to end without the LANL
dataset, which is about 8 GB and is not redistributable here.

**These samples demonstrate that the system runs and what its output looks
like. They do not reproduce the evaluation numbers in the main README.**
Those come from real Los Alamos National Laboratory data, linked there.

| File | Domain | Contents |
|---|---|---|
| `sample_traffic_clean.txt` | Network flow | 3 days of normal traffic, 4 devices with stable peers |
| `sample_traffic.txt` | Network flow | A normal day, plus one device sweeping 18 unseen hosts and sending 2.4 MB out |
| `sample_auth_clean.txt` | Identity | Normal Windows logons, each user reaching two usual machines |
| `sample_auth.txt` | Identity | Normal logons, plus a credential replayed from an unknown machine |
| `sample_agent_events_clean.txt` | AI agent | Four ordinary agent working sessions |
| `sample_agent_events.txt` | AI agent | The same, plus a hijacked agent reading untrusted input then exfiltrating |

## Run everything

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

## What you should see

- **Flow:** `10.0.2.10` confirmed on the type-diversity path, mapped to
  MITRE T1018 and T1021.004.
- **Identity:** `C199 -> C101` confirmed on the repetition path, mapped to
  T1550.002 (Pass-the-Hash).
- **Agent:** two confirmations including `TAINTED_SCOPE_EXPANSION`, mapped
  to MITRE ATLAS AML.T0051.001 and AML.T0086.
- **Audit:** all records verify intact.

Regenerate these files at any time with `python make_samples.py`.
