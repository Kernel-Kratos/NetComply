"""Tests for core/remediation.py. Owner: P3."""

from core.contracts import DeviceInfo, Finding, Severity, Status
from core.remediation import build_remediation


def _finding(rule_id: str, title: str, status: Status = Status.FAIL) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        status=status,
        severity=Severity.HIGH,
        field="management.telnet_enabled",
        observed_value=True,
    )


def test_template_block_for_cisco():
    device = DeviceInfo(device_id="d1", filename="sw.cfg", vendor="cisco")
    findings = [_finding("CIS-MGMT-02", "SSH version 2")]
    blocks = build_remediation(device, findings)
    assert len(blocks) == 1
    b = blocks[0]
    assert b.source == "template"
    assert b.disclaimer == "Suggested. Review and test before applying."
    assert "ip ssh version 2" in b.commands


def test_template_block_for_juniper():
    device = DeviceInfo(device_id="d2", filename="jr.conf", vendor="juniper")
    findings = [_finding("CIS-MGMT-02", "SSH version 2")]
    blocks = build_remediation(device, findings)
    assert len(blocks) == 1
    b = blocks[0]
    assert b.source == "template"
    assert b.disclaimer == "Suggested. Review and test before applying."
    assert any("protocol-version v2" in c for c in b.commands)


def test_template_block_for_mikrotik():
    device = DeviceInfo(device_id="d3", filename="mt.rsc", vendor="mikrotik")
    findings = [_finding("CIS-MGMT-01", "Telnet disabled")]
    blocks = build_remediation(device, findings)
    assert len(blocks) == 1
    b = blocks[0]
    assert b.source == "template"
    assert b.disclaimer == "Suggested. Review and test before applying."
    assert any("disable telnet" in c for c in b.commands)


def test_unknown_vendor_returns_empty_commands():
    device = DeviceInfo(device_id="d4", filename="x.cfg", vendor="unknown-vendor")
    findings = [_finding("CIS-MGMT-01", "Telnet disabled")]
    blocks = build_remediation(device, findings)
    assert len(blocks) == 1
    b = blocks[0]
    assert b.source == "llm"  # no template -> LLM fallback
    assert b.disclaimer == "Suggested. Review and test before applying."


def test_all_ten_rules_have_blocks():
    device = DeviceInfo(device_id="d5", filename="sw.cfg", vendor="cisco")
    rules = [
        "CIS-MGMT-01", "CIS-MGMT-02", "CIS-MGMT-03", "CIS-SNMP-01",
        "CIS-LOGGING-01", "CIS-TIME-01", "CIS-MGMT-04", "CIS-MGMT-05",
        "CIS-AUTH-01", "CIS-AUTH-02",
    ]
    findings = [_finding(rid, f"title {rid}") for rid in rules]
    blocks = build_remediation(device, findings)
    assert len(blocks) == 10
    for b in blocks:
        assert b.source == "template"
        assert b.disclaimer == "Suggested. Review and test before applying."
        assert len(b.commands) >= 1


def test_pass_finding_still_gets_remediation():
    device = DeviceInfo(device_id="d6", filename="sw.cfg", vendor="cisco")
    findings = [_finding("CIS-MGMT-02", "SSH version 2", status=Status.PASS)]
    blocks = build_remediation(device, findings)
    assert len(blocks) == 1
