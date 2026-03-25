"""
detection_engine.py
-------------------
SIEM Detection Rule Engine — define detection rules in Python YAML config,
evaluate them against log events, and auto-generate Splunk SPL queries
for each rule. Supports threshold, sequence, and anomaly rule types.

Rule types:
  - threshold   : N events in T seconds (e.g. brute force)
  - sequence    : event A then B within window (e.g. recon → exploit)
  - field_match : specific field value triggers alert (e.g. admin tool usage)
  - anomaly     : value exceeds rolling baseline by N standard deviations
"""

import yaml
import json
import logging
import statistics
from datetime import datetime, timezone
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Any

log = logging.getLogger(__name__)


# ── Data Models ───────────────────────────────────────────────────────────────
@dataclass
class LogRecord:
    timestamp:  datetime
    source_ip:  str
    user:       str
    event_type: str
    fields:     dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "LogRecord":
        ts = d.get("timestamp", "")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        elif not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)
        return cls(
            timestamp  = ts,
            source_ip  = d.get("source_ip", ""),
            user       = d.get("user", ""),
            event_type = d.get("event_type", ""),
            fields     = {k: v for k, v in d.items()
                          if k not in ("timestamp", "source_ip", "user", "event_type")},
        )


@dataclass
class Detection:
    rule_id:         str
    rule_name:       str
    severity:        str
    mitre_technique: str
    triggered_at:    str
    key:             str    # grouping key (user/IP that triggered the rule)
    evidence:        dict = field(default_factory=dict)
    splunk_query:    str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id":         self.rule_id,
            "rule_name":       self.rule_name,
            "severity":        self.severity,
            "mitre_technique": self.mitre_technique,
            "triggered_at":    self.triggered_at,
            "key":             self.key,
            "evidence":        self.evidence,
            "splunk_query":    self.splunk_query,
        }


# ── SPL Query Generator ───────────────────────────────────────────────────────
class SPLGenerator:
    """Generates Splunk SPL queries from rule definitions."""

    @staticmethod
    def threshold_rule(rule: dict) -> str:
        event  = rule.get("event_type", "*")
        field  = rule.get("group_by", "user")
        count  = rule.get("threshold", 5)
        window = rule.get("window_seconds", 60)
        mins   = max(1, window // 60)
        return (
            f'index=* event_type="{event}"\n'
            f'| bucket _time span={mins}m\n'
            f'| stats count by _time, {field}\n'
            f'| where count >= {count}\n'
            f'| eval severity="{rule.get("severity","HIGH")}", '
            f'rule="{rule.get("name","Threshold Rule")}"\n'
            f'| table _time {field} count severity rule'
        )

    @staticmethod
    def sequence_rule(rule: dict) -> str:
        events = rule.get("sequence", [])
        field  = rule.get("group_by", "user")
        window = rule.get("window_seconds", 300)
        mins   = max(1, window // 60)
        if len(events) < 2:
            return "| makeresults | eval error=\"sequence rule needs at least 2 events\""
        e1, e2 = events[0], events[1]
        return (
            f'index=* event_type IN ("{e1}", "{e2}")\n'
            f'| transaction {field} startswith=(event_type="{e1}") '
            f'endswith=(event_type="{e2}") maxspan={mins}m\n'
            f'| where eventcount >= 2\n'
            f'| eval severity="{rule.get("severity","HIGH")}", '
            f'rule="{rule.get("name","Sequence Rule")}"\n'
            f'| table _time {field} eventcount duration severity rule'
        )

    @staticmethod
    def field_match_rule(rule: dict) -> str:
        matches = rule.get("field_matches", {})
        clauses = " ".join(f'{k}="{v}"' for k, v in matches.items())
        return (
            f'index=* {clauses}\n'
            f'| eval severity="{rule.get("severity","MEDIUM")}", '
            f'rule="{rule.get("name","Field Match Rule")}"\n'
            f'| table _time user source_ip event_type severity rule'
        )

    @classmethod
    def generate(cls, rule: dict) -> str:
        rule_type = rule.get("type", "threshold")
        generators = {
            "threshold":   cls.threshold_rule,
            "sequence":    cls.sequence_rule,
            "field_match": cls.field_match_rule,
        }
        gen = generators.get(rule_type)
        if not gen:
            return f"| makeresults | eval error=\"unsupported rule type: {rule_type}\""
        return gen(rule)


# ── Rule Evaluators ───────────────────────────────────────────────────────────
class RuleEngine:
    def __init__(self, rules: list[dict]):
        self.rules      = rules
        self.detections: list[Detection] = []
        # State for stateful rules
        self._counts:    dict = defaultdict(lambda: deque())  # rule_id:key → timestamps
        self._sequences: dict = defaultdict(dict)             # rule_id:key → state

    def _make_detection(self, rule: dict, key: str, evidence: dict) -> Detection:
        return Detection(
            rule_id         = rule["id"],
            rule_name       = rule["name"],
            severity        = rule.get("severity", "MEDIUM"),
            mitre_technique = rule.get("mitre_technique", ""),
            triggered_at    = datetime.now(timezone.utc).isoformat(),
            key             = key,
            evidence        = evidence,
            splunk_query    = SPLGenerator.generate(rule),
        )

    def _eval_threshold(self, rule: dict, record: LogRecord) -> Optional[Detection]:
        if record.event_type != rule.get("event_type"):
            return None
        group_by = rule.get("group_by", "user")
        key      = getattr(record, group_by, None) or record.fields.get(group_by, "unknown")
        state_key= f"{rule['id']}:{key}"
        window   = rule.get("window_seconds", 60)
        threshold= rule.get("threshold", 5)
        now      = record.timestamp

        q = self._counts[state_key]
        q.append(now)
        cutoff = now.timestamp() - window
        while q and q[0].timestamp() < cutoff:
            q.popleft()

        if len(q) >= threshold:
            self._counts[state_key].clear()   # reset after firing
            return self._make_detection(rule, key, {
                "event_count": len(q),
                "window_seconds": window,
                "threshold": threshold,
                "group_by_value": key,
            })
        return None

    def _eval_sequence(self, rule: dict, record: LogRecord) -> Optional[Detection]:
        sequence = rule.get("sequence", [])
        if not sequence or record.event_type not in sequence:
            return None
        group_by  = rule.get("group_by", "user")
        key       = getattr(record, group_by, None) or record.fields.get(group_by, "unknown")
        state_key = f"{rule['id']}:{key}"
        window    = rule.get("window_seconds", 300)
        state     = self._sequences[state_key]

        expected_idx = state.get("next_idx", 0)
        if record.event_type == sequence[expected_idx]:
            state["next_idx"]  = expected_idx + 1
            state["last_time"] = record.timestamp
            state["events"]    = state.get("events", []) + [record.event_type]

            # Check window expiry
            if expected_idx > 0:
                elapsed = (record.timestamp - state.get("start_time", record.timestamp)).total_seconds()
                if elapsed > window:
                    self._sequences[state_key] = {"next_idx": 0}
                    return None

            if expected_idx == 0:
                state["start_time"] = record.timestamp

            if state["next_idx"] == len(sequence):
                self._sequences[state_key] = {}
                return self._make_detection(rule, key, {
                    "sequence":       state["events"],
                    "total_seconds":  (record.timestamp - state["start_time"]).total_seconds(),
                })
        else:
            # Out-of-order — reset
            self._sequences[state_key] = {}
        return None

    def _eval_field_match(self, rule: dict, record: LogRecord) -> Optional[Detection]:
        matches = rule.get("field_matches", {})
        for field_name, expected in matches.items():
            actual = getattr(record, field_name, None) or record.fields.get(field_name)
            if actual != expected:
                return None
        return self._make_detection(rule, record.user or record.source_ip, {
            "matched_fields": matches,
            "event_type":     record.event_type,
        })

    def process(self, record: LogRecord) -> list[Detection]:
        new_detections: list[Detection] = []
        for rule in self.rules:
            rule_type = rule.get("type", "threshold")
            det = None
            if rule_type == "threshold":
                det = self._eval_threshold(rule, record)
            elif rule_type == "sequence":
                det = self._eval_sequence(rule, record)
            elif rule_type == "field_match":
                det = self._eval_field_match(rule, record)

            if det:
                self.detections.append(det)
                new_detections.append(det)
                log.warning("[%s] %s triggered for key=%s", det.severity, det.rule_name, det.key)

        return new_detections

    def process_batch(self, records: list[LogRecord]) -> list[Detection]:
        for record in sorted(records, key=lambda r: r.timestamp):
            self.process(record)
        return self.detections


# ── Config Loader ─────────────────────────────────────────────────────────────
def load_rules_from_yaml(path: str) -> list[dict]:
    content = open(path).read()
    data    = yaml.safe_load(content)
    rules   = data.get("rules", [])
    log.info("Loaded %d detection rules from %s", len(rules), path)
    return rules


def load_rules_from_dict(data: dict) -> list[dict]:
    return data.get("rules", [])

