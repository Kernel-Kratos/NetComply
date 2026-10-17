"""Tests for core.compliance (rule loader + evaluator). Owner: P1.

Uses inline rules rather than rules/cis.yaml (P3's file).
"""

import tempfile
from pathlib import Path

import yaml
import pytest

from core.compliance import (
    ControlResult,
    Rule,
    _evaluate_one,
    evaluate,
    list_frameworks,
    load_rules,
)
from core.contracts import (
    DeviceInfo,
    Severity,
    Status,
)
from core.schema import (
    FieldValue,
    Logging,
    Management,
    SecurityBaseline,
)


def _baseline() -> SecurityBaseline:
    b = SecurityBaseline()
    b.management.telnet_enabled = FieldValue(
        value=False, source_line="no ip telnet", line_number=3, origin="mapping"
    )
    b.management.ssh_version = FieldValue(
        value=2, source_line="ip ssh version 2", line_number=7, origin="mapping"
    )
    b.management.http_server_enabled = FieldValue(
        value=True, source_line="ip http server", line_number=9, origin="mapping"
    )
    b.management.idle_timeout_min = FieldValue(
        value=5, source_line="exec-timeout 5", line_number=11, origin="mapping"
    )
    b.logging.syslog_servers = FieldValue(
        value=["10.0.0.5"], source_line="logging host 10.0.0.5", line_number=17, origin="mapping"
    )
    return b


def _rule(**kw) -> Rule:
    defaults = dict(
        id="T", title="t", field="management.telnet_enabled",
        op="eq", value=False, severity="high",
    )
    defaults.update(kw)
    return Rule(**defaults)


def test_unknown_field_is_unknown_no_evidence():
    b = SecurityBaseline()  # everything null
    res = _evaluate_one(b, _rule(field="management.telnet_enabled", op="eq", value=False))
    assert res.status == Status.UNKNOWN
    assert res.observed_value is None
    assert res.evidence is None


def test_operators():
    b = _baseline()
    cases = [
        ("management.telnet_enabled", "eq", False, True),   # telnet disabled == False
        ("management.telnet_enabled", "eq", True, False),
        ("management.telnet_enabled", "ne", True, True),    # telnet != True
        ("management.ssh_version", "gte", 2, True),         # ssh_version >= 2
        ("management.ssh_version", "gte", 3, False),
        ("management.ssh_version", "lte", 2, True),
        ("management.ssh_version", "lte", 1, False),
        ("management.ssh_version", "in", [2], True),        # ssh_version in [2]
        ("management.ssh_version", "in", [1], False),
        ("management.ssh_version", "not_in", [1], True),
        ("management.ssh_version", "not_in", [2], False),
        ("management.telnet_enabled", "exists", None, True),
        ("logging.syslog_servers", "empty", None, False),  # non-empty list -> not empty
    ]
    for field, op, value, expected_pass in cases:
        rule = _rule(field=field, op=op, value=value)
        res = _evaluate_one(b, rule)
        assert res.status == (Status.PASS if expected_pass else Status.FAIL), (field, op, value, res.status)


def test_empty_on_empty_list_is_true():
    b = _baseline()
    b.logging.syslog_servers = FieldValue(value=[], source_line="", line_number=0, origin="mapping")
    rule = _rule(field="logging.syslog_servers", op="empty", value=None)
    res = _evaluate_one(b, rule)
    assert res.status == Status.PASS


def test_evidence_attached_when_value_present():
    b = _baseline()
    rule = _rule(field="management.telnet_enabled", op="eq", value=False)
    res = _evaluate_one(b, rule)
    assert res.status == Status.PASS
    assert res.evidence is not None
    assert res.evidence["source_line"] == "no ip telnet"
    assert res.evidence["line_number"] == 3
    assert res.evidence["origin"] == "mapping"


def test_unknown_op_raises():
    b = _baseline()
    with pytest.raises(ValueError, match="Unknown operator"):
        _evaluate_one(b, _rule(op="bogus"))


def test_evaluate_filters_by_framework():
    b = _baseline()
    device = DeviceInfo(device_id="d1", filename="x.cfg", vendor="cisco")
    rules = [
        _rule(id="A", field="management.telnet_enabled", op="eq", value=False, frameworks={"CIS": "1.1"}),
        _rule(id="B", field="management.ssh_version", op="eq", value=2, frameworks={"NIST": "AC-17"}),
        _rule(id="C", field="management.http_server_enabled", op="eq", value=False, frameworks={"CIS": "1.2"}),
    ]
    result = evaluate(b, rules, "CIS", device)
    assert result.framework == "CIS"
    assert {f.rule_id for f in result.findings} == {"A", "C"}
    assert result.pass_count == 1   # A passes (telnet False==False); C fails (http True != False)
    assert result.fail_count == 1
    assert result.unknown_count == 0
    assert result.score == 50.0


def test_evaluate_all_unknown_score_none():
    b = SecurityBaseline()  # all null
    device = DeviceInfo(device_id="d1", filename="x.cfg", vendor="cisco")
    rules = [
        _rule(id="A", field="management.telnet_enabled", op="eq", value=False, frameworks={"CIS": "1.1"}),
        _rule(id="B", field="management.ssh_version", op="eq", value=2, frameworks={"CIS": "1.2"}),
    ]
    result = evaluate(b, rules, "CIS", device)
    assert result.unknown_count == 2
    assert result.pass_count == 0
    assert result.fail_count == 0
    assert result.score is None


def test_evaluate_2_pass_1_fail_3_unknown_score_66_7():
    b = _baseline()
    device = DeviceInfo(device_id="d1", filename="x.cfg", vendor="cisco")
    rules = [
        _rule(id="p1", field="management.telnet_enabled", op="eq", value=False, frameworks={"CIS": "1.1"}),   # pass
        _rule(id="p2", field="management.ssh_version", op="eq", value=2, frameworks={"CIS": "1.2"}),           # pass
        _rule(id="f1", field="management.http_server_enabled", op="eq", value=False, frameworks={"CIS": "1.3"}), # fail
        _rule(id="u1", field="snmp.v1_v2_enabled", op="eq", value=False, frameworks={"CIS": "1.4"}),           # unknown (null)
        _rule(id="u2", field="banner.login_banner_set", op="eq", value=False, frameworks={"CIS": "1.5"}),       # unknown (null)
        _rule(id="u3", field="crypto.weak_ciphers_enabled", op="eq", value=False, frameworks={"CIS": "1.6"}),   # unknown (null)
    ]
    result = evaluate(b, rules, "CIS", device)
    assert result.pass_count == 2
    assert result.fail_count == 1
    assert result.unknown_count == 3
    assert result.score == 66.7
    assert result.risk_level == Severity.HIGH  # one high severity failure


def test_evaluate_risk_level_low_when_no_failures():
    b = _baseline()
    device = DeviceInfo(device_id="d1", filename="x.cfg", vendor="cisco")
    rules = [
        _rule(id="p1", field="management.telnet_enabled", op="eq", value=False, frameworks={"CIS": "1.1", "severity": "critical"}),
    ]
    result = evaluate(b, rules, "CIS", device)
    assert result.risk_level == Severity.LOW


def test_load_rules_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_rules("rules/does_not_exist.yaml")


def test_load_rules_dir():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "a.yaml").write_text(
            '- id: A\n  title: a\n  field: management.telnet_enabled\n  op: eq\n  value: false\n  frameworks: {CIS: "1.1"}\n'
        )
        (d / "b.yaml").write_text(
            '- id: B\n  title: b\n  field: management.ssh_version\n  op: eq\n  value: 2\n  frameworks: {NIST: "AC-17"}\n'
        )
        rules = load_rules(str(d))
        assert {r.id for r in rules} == {"A", "B"}


def test_list_frameworks_dir():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "a.yaml").write_text(
            '- id: A\n  title: a\n  field: management.telnet_enabled\n  op: eq\n  value: false\n  frameworks: {CIS: "1.1", NIST: "AC-17"}\n'
        )
        (d / "b.yaml").write_text(
            '- id: B\n  title: b\n  field: management.ssh_version\n  op: eq\n  value: 2\n  frameworks: {CIS: "1.2"}\n'
        )
        assert list_frameworks(str(d)) == ["CIS", "NIST"]


def test_list_frameworks_missing_dir_returns_empty():
    assert list_frameworks("rules/does_not_exist") == []


def test_load_rules_rejects_invalid_field():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "bad.yaml").write_text(
            '- id: BAD\n  title: bad\n  field: management.nope_field\n  op: eq\n  value: false\n  frameworks: {CIS: "1.1"}\n'
        )
        with pytest.raises(ValueError, match="not a valid schema path"):
            load_rules(str(d))
