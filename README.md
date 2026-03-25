# SIEM Detection Rule Engine

**Python-based detection rule engine** that evaluates logs against MITRE ATT&CK-aligned rules defined in YAML — and automatically generates Splunk SPL queries for every rule.

---

## What It Does

- Evaluates raw log events against configurable detection rules (threshold, sequence, field match)
- Fires alerts when rules are triggered with full evidence and MITRE mapping
- **Auto-generates Splunk SPL** for every rule — export and import directly into Splunk
- Works standalone (no Splunk needed) and as a pre-processing layer before SIEM ingestion

---

## Detection Rules Included

| Rule ID | Name | Type | Severity | MITRE |
|---------|------|------|----------|-------|
| RULE-001 | Brute Force Login Attempt | threshold | HIGH | T1110 |
| RULE-002 | Password Spray | threshold | HIGH | T1110.003 |
| RULE-003 | Success After Multiple Failures | sequence | MEDIUM | T1078 |
| RULE-004 | Privilege Escalation → Admin Action | sequence | HIGH | T1078.004 |
| RULE-005 | MFA Device Disabled | field_match | HIGH | T1556 |
| RULE-006 | Bulk File Download | threshold | MEDIUM | T1567 |
| RULE-007 | Scan → Remote Login (Lateral Movement) | sequence | HIGH | T1021 |
| RULE-008 | Service Account Interactive Login | field_match | MEDIUM | T1078.003 |

---

## Quick Start

```bash
git clone https://github.com/YOUR-USERNAME/siem-detection-engine
cd siem-detection-engine
pip install -r requirements.txt

# Run built-in demo (no log files needed)
python main.py --demo

# Run against your own JSON log file
python main.py --logs sample_data/sample_logs.json --rules rules/detection_rules.yaml

# Export ALL rules as Splunk SPL .spl files
python main.py --export-spl

# Save detections to JSON
python main.py --demo --output detections.json
```

---

## Sample Output

```
═════════════════════════════════════════════════════════════════
  SIEM DETECTION ENGINE — RESULTS
═════════════════════════════════════════════════════════════════
  Detections: 5
  🟠 HIGH        : 4
  🟡 MEDIUM      : 1

🟠 [HIGH] RULE-001 — Brute Force Login Attempt
   Key       : 192.0.2.100
   MITRE     : T1110 — Brute Force
   Evidence  : {"event_count": 6, "window_seconds": 300, "threshold": 5}

   Splunk SPL:
   index=* event_type="login_failure"
   | bucket _time span=5m
   | stats count by _time, source_ip
   | where count >= 5
```

---

## Writing Your Own Rules

Add rules to `rules/detection_rules.yaml`:

```yaml
rules:
  - id: RULE-009
    name: My Custom Rule
    type: threshold
    severity: HIGH
    event_type: login_failure
    group_by: user
    threshold: 3
    window_seconds: 60
    mitre_technique: "T1110 — Brute Force"
    description: 3 failures in 60 seconds per user
```

The engine will evaluate it and generate its SPL automatically.

---

## Project Structure

```
siem-detection-engine/
├── main.py                          # CLI — run detection, export SPL
├── src/
│   └── detection_engine.py          # Rule engine, SPL generator, data models
├── rules/
│   └── detection_rules.yaml         # 8 MITRE ATT&CK-aligned detection rules
├── sample_data/
│   └── sample_logs.json             # Demo log events
├── spl_queries/                     # Auto-generated SPL files (after --export-spl)
├── tests/
│   └── test_detection_engine.py
├── requirements.txt
└── README.md
```

---

## Skills Demonstrated

`Python` · `Splunk SPL` · `SIEM` · `MITRE ATT&CK` · `Detection Engineering` · `Threat Detection` · `Security Automation` · `YAML` · `Log Analysis`

---

## Author

**Harshith Shiva** — Cybersecurity Engineer  
[LinkedIn](https://linkedin.com/in/YOUR-LINKEDIN) · [Portfolio](https://YOUR-PORTFOLIO-URL)
