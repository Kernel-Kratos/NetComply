"""Backend entry points. The frontend imports ONLY this module (via app/api.py).

Owner: P1. Signatures are frozen with core/contracts.py. Each function is
implemented as the pieces land; until then it raises NotImplementedError, and
the frontend uses app/mock_service.py (USE_MOCK_SERVICE=1).

P2/P3/P5 modules are imported lazily INSIDE each function so this file imports
fine before those modules exist. A missing module raises
NotImplementedError("waiting for core/<module>.py (<owner>)") with a clear
message instead of an opaque ImportError.
"""
from __future__ import annotations

import importlib
import logging
import threading
from typing import Any

from core.contracts import (
    DeviceInfo,
    DeviceResult,
    LLMStatus,
    MappingIn,
    MappingSuggestion,
    Severity,
    UnmappedLine,
    UploadedFile,
)

log = logging.getLogger(__name__)

RULES_DIR = "rules"


def _import_module(module: str, owner: str) -> Any:
    """Import a module owned by another person, failing with a clear message."""
    try:
        return importlib.import_module(module)
    except (ModuleNotFoundError, ImportError) as e:
        raise NotImplementedError(f"waiting for {module}.py ({owner})") from e


class _DeviceStore:
    """Thread-safe in-process store keyed by device_id."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data: dict[str, dict[str, Any]] = {}

    def get(self, device_id: str) -> dict[str, Any]:
        with self._lock:
            entry = self._data.get(device_id)
            if entry is None:
                raise KeyError(f"Unknown device_id: {device_id}")
            return entry

    def put(
        self,
        device_id: str,
        *,
        ingested: Any,
        baseline: Any,
        review_queue: list[UnmappedLine],
        result: DeviceResult,
    ) -> None:
        with self._lock:
            self._data[device_id] = {
                "ingested": ingested,
                "baseline": baseline,
                "review_queue": review_queue,
                "result": result,
            }


_STORE = _DeviceStore()


def list_frameworks() -> list[str]:
    from core.compliance import list_frameworks as _list_frameworks

    return _list_frameworks(RULES_DIR)


def audit_files(files: list[UploadedFile], framework: str) -> list[DeviceResult]:
    from core.compliance import load_rules, evaluate

    try:
        rules = load_rules(RULES_DIR)
    except Exception:
        log.exception("could not load rules from %s", RULES_DIR)
        rules = []

    results: list[DeviceResult] = []
    for file in files:
        device_id = file.filename
        try:
            ingest_mod = _import_module("core.ingest", "P2")
            dev = ingest_mod.ingest_file(file)
            norm_mod = _import_module("core.normalize", "P2")
            baseline, review_queue = norm_mod.normalize_device(dev)
            result = evaluate(baseline, rules, framework, dev.device)
            rem_mod = _import_module("core.remediation", "P3")
            result.remediation = rem_mod.build_remediation(dev.device, result.findings)
            result.review_queue_count = len(review_queue)
            _STORE.put(
                device_id=device_id,
                ingested=dev,
                baseline=baseline,
                review_queue=review_queue,
                result=result,
            )
        except Exception as e:  # one bad file must not kill the batch
            log.exception("audit failed for %s: nothing is guessed", device_id)
            result = DeviceResult(
                device=DeviceInfo(device_id=device_id, filename=file.filename),
                framework=framework,
                score=None,
                risk_level=Severity.LOW,
                pass_count=0,
                fail_count=0,
                unknown_count=len(rules),
                findings=[],
                remediation=[],
                review_queue_count=0,
            )
            try:
                _STORE.put(
                    device_id=device_id,
                    ingested=None,
                    baseline=None,
                    review_queue=[],
                    result=result,
                )
            except Exception:
                pass
        results.append(result)
    return results


def get_review_queue(device_id: str) -> list[UnmappedLine]:
    return _STORE.get(device_id)["review_queue"]


def suggest_mapping(line: UnmappedLine) -> MappingSuggestion:
    norm_mod = _import_module("core.normalize", "P2")
    return norm_mod.suggest_mapping(line)


def save_mapping(mapping: MappingIn) -> None:
    mappings_mod = _import_module("core.mappings", "P2")
    mappings_mod.save_mapping(mapping)


def reaudit(device_ids: list[str], framework: str) -> list[DeviceResult]:
    from core.compliance import load_rules, evaluate

    try:
        rules = load_rules(RULES_DIR)
    except Exception:
        log.exception("could not load rules from %s", RULES_DIR)
        rules = []

    results: list[DeviceResult] = []
    for device_id in device_ids:
        entry = _STORE.get(device_id)  # raises KeyError if unknown
        ingested = entry["ingested"]
        norm_mod = _import_module("core.normalize", "P2")
        baseline, review_queue = norm_mod.normalize_device(ingested)
        result = evaluate(baseline, rules, framework, ingested.device)
        rem_mod = _import_module("core.remediation", "P3")
        result.remediation = rem_mod.build_remediation(ingested.device, result.findings)
        result.review_queue_count = len(review_queue)
        _STORE.put(
            device_id=device_id,
            ingested=ingested,
            baseline=baseline,
            review_queue=review_queue,
            result=result,
        )
        results.append(result)
    return results


def generate_report(device_id: str) -> bytes:
    entry = _STORE.get(device_id)  # raises KeyError if unknown
    report_mod = _import_module("core.report", "P5")
    return report_mod.build_pdf(entry["result"])


def llm_status() -> LLMStatus:
    from core.llm.client import LLMClient, LLMError

    try:
        status = LLMClient().status()
    except LLMError:
        cfg = __import__("core.llm.client", fromlist=["load_config"]).load_config()
        return LLMStatus(
            backend=cfg.backend,
            model="(none)",
            offline_mode=cfg.offline,
            ready=False,
        )
    return LLMStatus(**status)
