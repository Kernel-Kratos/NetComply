"""Tests for rules/cis.yaml loading through compliance.load_rules(). Owner: P3."""

from pathlib import Path

import pytest

from core.compliance import load_rules
from core.schema import rule_paths


def test_cis_yaml_loads():
    rules = load_rules("rules/cis.yaml")
    assert len(rules) == 10


def test_all_fields_are_valid_rule_paths():
    rules = load_rules("rules/cis.yaml")
    allowed = rule_paths()
    for rule in rules:
        assert rule.field in allowed, f"Invalid field path: {rule.field}"


def test_all_ops_are_supported():
    rules = load_rules("rules/cis.yaml")
    supported = {"eq", "ne", "gte", "lte", "in", "not_in", "exists", "empty"}
    for rule in rules:
        assert rule.op in supported, f"Unsupported op {rule.op} in {rule.id}"


def test_every_rule_has_remediation_id():
    rules = load_rules("rules/cis.yaml")
    for rule in rules:
        assert rule.remediation is not None, f"Rule {rule.id} missing remediation id"


def test_every_remediation_id_has_cisco_template():
    rules = load_rules("rules/cis.yaml")
    templates_path = Path("templates/remediation/cisco.yaml")
    import yaml
    with open(templates_path) as fh:
        templates = yaml.safe_load(fh) or {}
    for rule in rules:
        assert rule.remediation in templates, (
            f"No Cisco template for remediation id {rule.remediation}"
        )


def test_remediation_ids_match_template_keys():
    rules = load_rules("rules/cis.yaml")
    import yaml
    for vendor in ("cisco", "juniper", "mikrotik"):
        path = Path(f"templates/remediation/{vendor}.yaml")
        with open(path) as fh:
            templates = yaml.safe_load(fh) or {}
        for rule in rules:
            assert rule.remediation in templates, (
                f"Missing {vendor} template for remediation id {rule.remediation}"
            )


def test_invalid_field_rejected():
    import tempfile
    d = Path(tempfile.mkdtemp())
    bad = d / "bad.yaml"
    bad.write_text(
        '- id: BAD\n  title: bad\n  field: management.nope_field\n  op: eq\n  value: false\n'
    )
    with pytest.raises(ValueError, match="not a valid schema path"):
        load_rules(str(bad))


def test_device_fields_rejected():
    import tempfile
    d = Path(tempfile.mkdtemp())
    bad = d / "bad2.yaml"
    bad.write_text(
        '- id: BAD2\n  title: bad\n  field: device.vendor\n  op: eq\n  value: x\n'
    )
    with pytest.raises(ValueError, match="not a valid schema path"):
        load_rules(str(bad))
