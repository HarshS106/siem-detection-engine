"""
main.py
-------
CLI for the SIEM Detection Rule Engine.

Usage:
    # Run detection against a JSON log file
    python main.py --logs sample_data/sample_logs.json --rules rules/detection_rules.yaml

    # Export all rules as Splunk SPL queries
    python main.py --rules rules/detection_rules.yaml --export-spl

    # Run built-in demo (no files needed)
    python main.py --demo

    # Save detections to JSON
    python main.py --logs sample_data/sample_logs.json --rules rules/detection_rules.yaml --output detections.json
"""

import sys
import json
import argparse
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent))
from src.detection_engine import RuleEngine, LogRecord, SPLGenerator, load_rules_from_yaml

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


# ── Demo Log Generator ────────────────────────────────────────────────────────
def generate_demo_logs() -> list[dict]:
    """Generate synthetic log events that will trigger all rule types."""
    base = datetime.now(timezone.utc)
    logs = []

    # Trigger RULE-001: 6 login failures from same IP in 3 minutes
    for i in range(6):
        logs.append({
            "timestamp":  (base + timedelta(seconds=i * 25)).isoformat(),
            "event_type": "login_failure",
            "user":       "alice@company.com",
            "source_ip":  "192.0.2.100",
        })

    # Trigger RULE-003: failure then success for same user
    logs.append({
        "timestamp":  (base + timedelta(seconds=200)).isoformat(),
        "event_type": "login_failure",
        "user":       "bob@company.com",
        "source_ip":  "203.0.113.55",
    })
    logs.append({
        "timestamp":  (base + timedelta(seconds=210)).isoformat(),
        "event_type": "login_success",
        "user":       "bob@company.com",
        "source_ip":  "203.0.113.55",
    })

    # Trigger RULE-004: role assigned then admin action
    logs.append({
        "timestamp":  (base + timedelta(minutes=5)).isoformat(),
        "event_type": "role_assigned",
        "user":       "carol@company.com",
        "source_ip":  "10.0.0.5",
        "new_role":   "SecurityAdmin",
    })
    logs.append({
        "timestamp":  (base + timedelta(minutes=8)).isoformat(),
        "event_type": "admin_action",
        "user":       "carol@company.com",
        "source_ip":  "10.0.0.5",
        "action":     "modify_policy",
    })

    # Trigger RULE-005: MFA disabled
    logs.append({
        "timestamp":  (base + timedelta(minutes=10)).isoformat(),
        "event_type": "mfa_disabled",
        "user":       "dave@company.com",
        "source_ip":  "198.51.100.77",
    })

    # Trigger RULE-007: network scan then remote login
    logs.append({
        "timestamp":  (base + timedelta(minutes=15)).isoformat(),
        "event_type": "network_scan",
        "user":       "unknown",
        "source_ip":  "172.16.0.50",
    })
    logs.append({
        "timestamp":  (base + timedelta(minutes=16)).isoformat(),
        "event_type": "remote_login",
        "user":       "admin",
        "source_ip":  "172.16.0.50",
    })

    return logs


def print_detections(detections) -> None:
    counts = Counter(d.severity for d in detections)
    print("\n" + "═" * 65)
    print("  SIEM DETECTION ENGINE — RESULTS")
    print("═" * 65)
    print(f"  Detections: {len(detections)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = counts.get(sev, 0)
        if n:
            print(f"  {SEVERITY_ICONS[sev]} {sev:<10}: {n}")
    print("═" * 65)

    for d in detections:
        icon = SEVERITY_ICONS.get(d.severity, "⚪")
        print(f"\n{icon} [{d.severity}] {d.rule_id} — {d.rule_name}")
        print(f"   Key       : {d.key}")
        print(f"   Time      : {d.triggered_at}")
        print(f"   MITRE     : {d.mitre_technique}")
        print(f"   Evidence  : {json.dumps(d.evidence)}")
        print(f"\n   Splunk SPL:\n   " + d.splunk_query.replace("\n", "\n   "))

    print("\n" + "═" * 65 + "\n")


def export_spl(rules: list[dict], output_dir: str = "spl_queries") -> None:
    """Export each rule as a .spl file for import into Splunk."""
    Path(output_dir).mkdir(exist_ok=True)
    for rule in rules:
        spl      = SPLGenerator.generate(rule)
        filename = f"{rule.get('id', 'RULE')}-{rule.get('name','').replace(' ','_')}.spl"
        filepath = Path(output_dir) / filename
        header   = (
            f"-- Rule: {rule.get('name')}\n"
            f"-- ID:   {rule.get('id')}\n"
            f"-- MITRE: {rule.get('mitre_technique','')}\n"
            f"-- Severity: {rule.get('severity','')}\n\n"
        )
        filepath.write_text(header + spl)
        log.info("Exported → %s", filepath)
    print(f"\n✅ Exported {len(rules)} SPL queries to ./{output_dir}/\n")


def main():
    parser = argparse.ArgumentParser(
        description="SIEM Detection Rule Engine — evaluate logs + generate Splunk SPL"
    )
    parser.add_argument("--rules",      default="rules/detection_rules.yaml",
                        help="YAML rules file (default: rules/detection_rules.yaml)")
    parser.add_argument("--logs",       default=None,
                        help="JSON log file to evaluate")
    parser.add_argument("--output",     default=None,
                        help="Save detections to JSON file")
    parser.add_argument("--export-spl", action="store_true",
                        help="Export all rules as Splunk SPL .spl files")
    parser.add_argument("--demo",       action="store_true",
                        help="Run with built-in synthetic logs (no files needed)")
    args = parser.parse_args()

    # Load rules
    rules_path = Path(args.rules)
    if not rules_path.exists():
        log.error("Rules file not found: %s", rules_path)
        sys.exit(1)
    rules = load_rules_from_yaml(str(rules_path))

    # SPL export mode
    if args.export_spl:
        export_spl(rules)
        return

    # Load log records
    if args.demo:
        log.info("Using built-in demo logs")
        raw_logs = generate_demo_logs()
    elif args.logs:
        raw_logs = json.loads(Path(args.logs).read_text())
        if isinstance(raw_logs, dict):
            raw_logs = raw_logs.get("events", raw_logs.get("Records", []))
    else:
        parser.print_help()
        sys.exit(1)

    records    = [LogRecord.from_dict(r) for r in raw_logs]
    log.info("Processing %d log records against %d rules", len(records), len(rules))

    engine     = RuleEngine(rules)
    detections = engine.process_batch(records)

    print_detections(detections)

    if args.output:
        report = {
            "engine":     "SIEM Detection Rule Engine",
            "version":    "1.0.0",
            "ran_at":     datetime.now(timezone.utc).isoformat(),
            "rules_used": len(rules),
            "logs_processed": len(records),
            "detections": [d.to_dict() for d in detections],
        }
        Path(args.output).write_text(json.dumps(report, indent=2))
        log.info("Report saved → %s", args.output)


if __name__ == "__main__":
    main()
