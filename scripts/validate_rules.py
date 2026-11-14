#!/usr/bin/env python3
"""Validate public spam-detection rules without accessing any mailbox."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "rules/filter-rules.json").read_text(encoding="utf-8"))
assert data["schemaVersion"] == "1.0.0"
assert data["privacy"]["publicRepository"] is True
assert data["privacy"]["privateDataAllowed"] is False
assert data["activationPolicy"]["automaticMailboxActions"] is False
assert data["activationPolicy"]["requireLegitimateCounterexampleReview"] is True
assert data["activationPolicy"]["requireRegressionTests"] is True
assert isinstance(data["rules"], list) and data["rules"]
ids = set()
for rule in data["rules"]:
    assert isinstance(rule["id"], str) and rule["id"]
    assert rule["id"] not in ids, "duplicate rule id"
    ids.add(rule["id"])
    assert rule["status"] in {"signal_only", "candidate", "active"}
    assert rule["privateDataExcluded"] is True
    assert isinstance(rule["requiredCombination"], str) and rule["requiredCombination"]
    assert isinstance(rule["verdictEffect"], str) and rule["verdictEffect"]
    assert isinstance(rule["indicators"], dict) and rule["indicators"]
    assert "review" in rule["verdictEffect"].lower() or rule["status"] == "active"
print(f"Validated {len(ids)} detection rules; mailbox actions disabled.")
