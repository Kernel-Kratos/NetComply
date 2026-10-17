"""Tests for core.service (backend entry points). Owner: P1.

Injects fake P2/P3/P5 modules via sys.modules monkeypatch so service.py can be
tested without those modules existing.
"""

import sys
import types

import pytest

from core.service import _STORE, _import_module, audit_files, generate_report, get_review_queue, list_frameworks, reaudit, save_mapping, suggest_mapping
from core.contracts import (
    DeviceInfo,
    Finding,
    MappingIn,
    MappingSuggestion,
    RemediationBlock,
    Severity,
    Status,
    UnmappedLine,
    UploadedFile,
)


def _inject_fakes(monkeypatch):
    """Inject fake core.ingest, core.normalize, core.remediation, core.report."""

    # ---- core.ingest ----
    ingest = types.ModuleType("core.ingest")

    class IngestedDevice:
        def __init__(self, device, redacted_lines, blocks):
            self.device = device
            self.redacted_lines = redacted_lines
            self.blocks = blocks

    def ingest_file(file):
        dev = DeviceInfo(device_id="dev-1", filename=file.filename, vendor="cisco")
        return IngestedDevice(
            device=dev,
            redacted_lines=[file.content.decode()],
            blocks=[],
        )

    ingest.IngestedDevice = IngestedDevice
    ingest.ingest_file = ingest_file
    monkeypatch.setitem(sys.modules, "core.ingest", ingest)

    # ---- core.normalize ----
    normalize = types.ModuleType("core.normalize")

    def normalize_device(dev):
        from core.schema import SecurityBaseline
        baseline = SecurityBaseline()
        rq = [
            UnmappedLine(device_id="dev-1", line_number=1, raw_line="unknown line"),
        ]
        return baseline, rq

    def suggest_mapping(line):
        return MappingSuggestion(
            target_field="management.telnet_enabled",
            value_capture="bool",
            confidence=0.9,
            rationale="fake",
        )

    normalize.normalize_device = normalize_device
    normalize.suggest_mapping = suggest_mapping
    monkeypatch.setitem(sys.modules, "core.normalize", normalize)

    # ---- core.remediation ----
    remediation = types.ModuleType("core.remediation")

    def build_remediation(device, findings):
        return [
            RemediationBlock(
                rule_id="CIS-MGMT-01",
                vendor="cisco",
                commands=["no ip telnet"],
                source="template",
            )
        ]

    remediation.build_remediation = build_remediation
    monkeypatch.setitem(sys.modules, "core.remediation", remediation)

    # ---- core.report ----
    report = types.ModuleType("core.report")

    def build_pdf(result):
        return b"PDF-FOR-" + result.framework.encode()

    report.build_pdf = build_pdf
    monkeypatch.setitem(sys.modules, "core.report", report)


def _file(name, content=b"x"):
    return UploadedFile(filename=name, content=content)


def test_list_frameworks_missing_rules_dir(monkeypatch):
    monkeypatch.delenv("LLM_BACKEND", raising=False)
    frameworks = list_frameworks()
    assert "CIS" in frameworks
    assert "NIST" in frameworks


def test_audit_files_stores_and_returns(monkeypatch, tmp_path):
    _inject_fakes(monkeypatch)
    _STORE._data.clear()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "cis.yaml").write_text(
        '- id: CIS-MGMT-01\n  title: Telnet disabled\n  field: management.telnet_enabled\n  op: eq\n  value: false\n  frameworks: {CIS: "1.1"}\n'
    )
    monkeypatch.setattr("core.service.RULES_DIR", str(rules_dir))

    results = audit_files([_file("sw1.cfg")], "CIS")
    assert len(results) == 1
    r = results[0]
    assert r.framework == "CIS"
    assert r.review_queue_count == 1
    assert len(r.remediation) == 1
    assert r.remediation[0].rule_id == "CIS-MGMT-01"

    # store lookup works
    entry = _STORE.get("sw1.cfg")
    assert entry["result"] is r
    assert len(entry["review_queue"]) == r.review_queue_count == 1


def test_audit_files_error_isolation(monkeypatch, tmp_path):
    _inject_fakes(monkeypatch)
    _STORE._data.clear()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "cis.yaml").write_text(
        '- id: CIS-MGMT-01\n  title: Telnet disabled\n  field: management.telnet_enabled\n  op: eq\n  value: false\n  frameworks: {CIS: "1.1"}\n'
    )
    monkeypatch.setattr("core.service.RULES_DIR", str(rules_dir))

    # Make the fake ingest raise for the second file
    import core.ingest as ingest_mod
    orig = ingest_mod.ingest_file

    def boom(file):
        if file.filename == "bad.cfg":
            raise RuntimeError("ingest boom")
        return orig(file)

    ingest_mod.ingest_file = boom
    monkeypatch.setitem(sys.modules, "core.ingest", ingest_mod)

    results = audit_files([_file("good.cfg"), _file("bad.cfg")], "CIS")
    assert len(results) == 2
    good, bad = results
    assert good.framework == "CIS"
    assert bad.framework == "CIS"
    assert bad.score is None
    assert bad.unknown_count == 1  # one rule -> all unknown
    assert bad.findings == []
    # nothing guessed
    assert all(f.status != Status.PASS for f in bad.findings)


def test_get_review_queue(monkeypatch):
    _inject_fakes(monkeypatch)
    _STORE._data.clear()
    rules_dir = __import__("tempfile").mkdtemp()
    import pathlib
    pathlib.Path(rules_dir, "cis.yaml").write_text(
        '- id: CIS-MGMT-01\n  title: t\n  field: management.telnet_enabled\n  op: eq\n  value: false\n  frameworks: {CIS: "1.1"}\n'
    )
    monkeypatch.setattr("core.service.RULES_DIR", rules_dir)
    audit_files([_file("sw1.cfg")], "CIS")
    q = get_review_queue("sw1.cfg")
    assert len(q) == 1
    assert q[0].raw_line == "unknown line"


def test_get_review_queue_unknown_device_raises_keyerror():
    _STORE._data.clear()
    try:
        get_review_queue("nope")
    except KeyError as e:
        assert "Unknown device_id" in str(e)
    else:
        raise AssertionError("expected KeyError")


def test_suggest_mapping_delegates(monkeypatch):
    _inject_fakes(monkeypatch)
    line = UnmappedLine(device_id="d", line_number=1, raw_line="x")
    s = suggest_mapping(line)
    assert s.target_field == "management.telnet_enabled"
    assert s.confidence == 0.9


def test_save_mapping_delegates(monkeypatch):
    _inject_fakes(monkeypatch)
    mappings = types.ModuleType("core.mappings")
    calls = []

    def save_mapping(m):
        calls.append(m)

    mappings.save_mapping = save_mapping
    monkeypatch.setitem(sys.modules, "core.mappings", mappings)
    m = MappingIn(vendor="cisco", line_regex=r"^no telnet", target_field="management.telnet_enabled")
    save_mapping(m)
    assert calls[0] is m


def test_reaudit_reruns_normalize_and_evaluate(monkeypatch, tmp_path):
    _inject_fakes(monkeypatch)
    _STORE._data.clear()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "cis.yaml").write_text(
        '- id: CIS-MGMT-01\n  title: Telnet disabled\n  field: management.telnet_enabled\n  op: eq\n  value: false\n  frameworks: {CIS: "1.1"}\n'
    )
    monkeypatch.setattr("core.service.RULES_DIR", str(rules_dir))

    audit_files([_file("sw1.cfg")], "CIS")
    results = reaudit(["sw1.cfg"], "CIS")
    assert len(results) == 1
    assert results[0].framework == "CIS"


def test_reaudit_unknown_device_raises_keyerror():
    _STORE._data.clear()
    try:
        reaudit(["nope"], "CIS")
    except KeyError as e:
        assert "Unknown device_id" in str(e)
    else:
        raise AssertionError("expected KeyError")


def test_generate_report_delegates(monkeypatch):
    _inject_fakes(monkeypatch)
    _STORE._data.clear()
    rules_dir = __import__("tempfile").mkdtemp()
    import pathlib
    pathlib.Path(rules_dir, "cis.yaml").write_text(
        '- id: CIS-MGMT-01\n  title: t\n  field: management.telnet_enabled\n  op: eq\n  value: false\n  frameworks: {CIS: "1.1"}\n'
    )
    monkeypatch.setattr("core.service.RULES_DIR", rules_dir)
    audit_files([_file("sw1.cfg")], "CIS")
    pdf = generate_report("sw1.cfg")
    assert pdf == b"PDF-FOR-CIS"


def test_generate_report_unknown_device_raises_keyerror():
    _STORE._data.clear()
    try:
        generate_report("nope")
    except KeyError as e:
        assert "Unknown device_id" in str(e)
    else:
        raise AssertionError("expected KeyError")


def test_import_module_missing_raises_not_implemented():
    sys.modules.pop("core.normalize", None)
    try:
        _import_module("core.normalize", "P2")
    except NotImplementedError as e:
        assert "core.normalize" in str(e)
        assert "P2" in str(e)
    else:
        raise AssertionError("expected NotImplementedError")


def test_suggest_mapping_raises_when_module_missing(monkeypatch):
    for mod in ("core.normalize",):
        sys.modules.pop(mod, None)
    line = UnmappedLine(device_id="d", line_number=1, raw_line="x")
    try:
        suggest_mapping(line)
    except NotImplementedError as e:
        assert "core.normalize" in str(e)
        assert "P2" in str(e)
    else:
        raise AssertionError("expected NotImplementedError")
