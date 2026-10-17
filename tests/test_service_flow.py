"""End-to-end service flow test (P1).

Runs audit_files on the three samples -> get_review_queue (MikroTik) ->
save_mapping -> reaudit. Confirms the MikroTik score changes after a mapping
is saved.

Blocked until P2 delivers core/ingest.py, core/normalize.py, core/mappings.py
and P3 delivers samples/ and rules/cis.yaml. These are imported lazily inside
service.py, so this file imports fine now but audit_files will raise
NotImplementedError until those modules exist.
"""

from core.contracts import MappingIn, Status, UploadedFile
from core.service import audit_files, generate_report, get_review_queue, reaudit, save_mapping


def _sample(name: str) -> UploadedFile:
    return UploadedFile(filename=name, content=b"placeholder")


def test_full_flow_mikrotik_score_changes_after_mapping():
    """Full flow: audit -> review queue -> save mapping -> reaudit.

    The MikroTik golden starts with unmatched lines in the review queue.
    After save_mapping, reaudit should apply the mapping and change the score.
    """
    results = audit_files(
        [
            _sample("samples/cisco_ios.cfg"),
            _sample("samples/juniper.conf"),
            _sample("samples/mikrotik.rsc"),
        ],
        "CIS",
    )
    assert len(results) == 3

    # MikroTik should have items in the review queue (unmatched lines).
    mt = [r for r in results if r.device.filename == "samples/mikrotik.rsc"][0]
    q = get_review_queue(mt.device.device_id)
    assert len(q) > 0, "MikroTik should start with unmatched lines in review queue"

    score_before = mt.score

    # Save a mapping for one of MikroTik's unmatched lines.
    save_mapping(
        MappingIn(
            vendor="mikrotik",
            os_pattern="*",
            line_regex=r"^/ip service disable telnet$",
            target_field="management.telnet_enabled",
            value_capture="bool",
            created_by="admin",
        )
    )

    # Reaudit: the new mapping should apply.
    results2 = reaudit([mt.device.device_id], "CIS")
    mt2 = results2[0]
    assert mt2.score != score_before, "MikroTik score must change after mapping is saved"


def test_generate_report_returns_pdf_bytes():
    results = audit_files([_sample("samples/cisco_ios.cfg")], "CIS")
    r = results[0]
    pdf = generate_report(r.device.device_id)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")


def test_unknown_findings_have_no_evidence_and_not_counted_as_pass():
    results = audit_files([_sample("samples/cisco_ios.cfg")], "CIS")
    for r in results:
        for f in r.findings:
            if f.status == Status.UNKNOWN:
                assert f.evidence is None, f"UNKNOWN finding {f.rule_id} must have evidence=None"
