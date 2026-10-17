"""Compliance engine: loads YAML rules and evaluates them against a baseline.

Owner: P1. Rules are data (YAML), not code. Operators are plain functions;
no eval/exec of expression strings (AGENTS.md sections 9, 14).

Evaluation returns pass / fail / unknown (when the field value is null).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from core.contracts import (
    DeviceInfo,
    DeviceResult,
    Evidence,
    Finding,
    Severity,
    Status,
)
from core.schema import FieldValue, SecurityBaseline, rule_paths


class Rule(BaseModel):
    """A single compliance control, loaded from rules/*.yaml."""

    id: str
    title: str
    frameworks: dict[str, str] = {}
    field: str
    op: str
    value: Any = None
    severity: str = "medium"
    remediation: str | None = None


class ControlResult(BaseModel):
    """Outcome of evaluating one rule against one baseline."""

    rule_id: str
    title: str
    frameworks: dict[str, str] = {}
    field: str
    status: Status
    severity: Severity
    observed_value: Any = None
    evidence: dict[str, Any] | None = None


# Closed operator set. Each takes (observed, rule_value) -> bool.
_OPERATORS: dict[str, Any] = {}


def _register(op: str) -> Any:
    def deco(fn: Any) -> Any:
        _OPERATORS[op] = fn
        return fn

    return deco


@_register("eq")
def _eq(observed: Any, rule_value: Any) -> bool:
    return observed == rule_value


@_register("ne")
def _ne(observed: Any, rule_value: Any) -> bool:
    return observed != rule_value


@_register("gte")
def _gte(observed: Any, rule_value: Any) -> bool:
    try:
        return observed >= rule_value  # type: ignore[operator]
    except TypeError:
        return False


@_register("lte")
def _lte(observed: Any, rule_value: Any) -> bool:
    try:
        return observed <= rule_value  # type: ignore[operator]
    except TypeError:
        return False


@_register("in")
def _in(observed: Any, rule_value: Any) -> bool:
    if not isinstance(rule_value, (list, tuple, set)):
        return False
    return observed in rule_value


@_register("not_in")
def _not_in(observed: Any, rule_value: Any) -> bool:
    if not isinstance(rule_value, (list, tuple, set)):
        return True
    return observed not in rule_value


@_register("exists")
def _exists(observed: Any, rule_value: Any) -> bool:
    return observed is not None


@_register("empty")
def _empty(observed: Any, rule_value: Any) -> bool:
    if observed is None:
        return True
    if isinstance(observed, (list, tuple, set, str, dict)):
        return len(observed) == 0  # type: ignore[arg-type]
    return False


def _load_file(path: str) -> list[Rule]:
    """Load rules from a single YAML file. Fails loudly on bad input."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or []
    if not isinstance(data, list):
        raise ValueError(f"Rules file {path} must contain a list of controls")
    rules: list[Rule] = []
    allowed = rule_paths()
    for item in data:
        if not isinstance(item, dict):
            raise ValueError(
                f"Invalid rule in {path}: each item must be a mapping"
            )
        try:
            rule = Rule(**item)
        except ValidationError as e:
            raise ValueError(f"Invalid rule in {path}: {e}") from e
        if rule.field not in allowed:
            raise ValueError(
                f"Invalid rule in {path}: field '{rule.field}' is not a valid schema path"
            )
        rules.append(rule)
    return rules


def load_rules(path_or_dir: str) -> list[Rule]:
    """Load rules from a YAML file or a directory of YAML files.

    Fails loudly on a missing path or a directory with no rule files.
    """
    p = Path(path_or_dir)
    if not p.exists():
        raise FileNotFoundError(f"Rules path not found: {path_or_dir}")
    if p.is_dir():
        files = sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml"))
        if not files:
            raise ValueError(f"No rule files found in directory: {path_or_dir}")
        rules: list[Rule] = []
        for f in files:
            rules.extend(_load_file(str(f)))
        return rules
    return _load_file(str(p))


def list_frameworks(rules_dir: str) -> list[str]:
    """Return sorted unique framework keys referenced in a rules directory.

    Returns [] if the folder does not exist.
    """
    p = Path(rules_dir)
    if not p.exists():
        return []
    frameworks: set[str] = set()
    for f in sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")):
        for rule in _load_file(str(f)):
            frameworks.update(rule.frameworks.keys())
    return sorted(frameworks)


def _resolve_field(baseline: SecurityBaseline, field: str) -> Any:
    """Return the FieldValue for a dotted schema path, or None if not found."""
    node: Any = baseline
    for part in field.split("."):
        if not isinstance(node, BaseModel) or not hasattr(node, part):
            return None
        node = getattr(node, part)
    return node if isinstance(node, FieldValue) else None


def _evaluate_one(baseline: SecurityBaseline, rule: Rule) -> ControlResult:
    """Evaluate one rule against one baseline -> ControlResult."""
    field_value = _resolve_field(baseline, rule.field)
    observed = field_value.value if field_value is not None else None

    if observed is None:
        return ControlResult(
            rule_id=rule.id,
            title=rule.title,
            frameworks=rule.frameworks,
            field=rule.field,
            status=Status.UNKNOWN,
            severity=_sev(rule.severity),
            observed_value=None,
            evidence=None,
        )

    op_fn = _OPERATORS.get(rule.op)
    if op_fn is None:
        raise ValueError(f"Unknown operator '{rule.op}' in rule {rule.id}")

    passed = bool(op_fn(observed, rule.value))
    status = Status.PASS if passed else Status.FAIL

    evidence: dict[str, Any] | None = None
    if field_value is not None:
        evidence = {
            "source_line": field_value.source_line,
            "line_number": field_value.line_number,
            "confidence": field_value.confidence,
            "origin": field_value.origin,
        }

    return ControlResult(
        rule_id=rule.id,
        title=rule.title,
        frameworks=rule.frameworks,
        field=rule.field,
        status=status,
        severity=_sev(rule.severity),
        observed_value=observed,
        evidence=evidence,
    )


def _to_finding(cr: ControlResult) -> Finding:
    evidence: Evidence | None = None
    if cr.evidence is not None:
        evidence = Evidence(
            source_line=cr.evidence.get("source_line", ""),
            line_number=cr.evidence.get("line_number"),
            confidence=cr.evidence.get("confidence", 0.0),
            origin=cr.evidence.get("origin", "llm"),
        )
    return Finding(
        rule_id=cr.rule_id,
        title=cr.title,
        frameworks=cr.frameworks,
        status=cr.status,
        severity=cr.severity,
        field=cr.field,
        observed_value=cr.observed_value,
        evidence=evidence,
    )


_SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def _risk_level_from_findings(findings: list[Finding]) -> Severity:
    """Highest severity among FAILED findings, LOW if none."""
    failed = [f for f in findings if f.status == Status.FAIL]
    if not failed:
        return Severity.LOW
    return max(failed, key=lambda f: _SEVERITY_ORDER[f.severity]).severity


def evaluate(
    baseline: SecurityBaseline,
    rules: list[Rule],
    framework: str,
    device: DeviceInfo,
) -> DeviceResult:
    """Evaluate all rules referencing ``framework`` against a baseline.

    Returns a DeviceResult with findings, counts, score, and risk_level.
    Remediation is left empty (filled by P3's remediation.py later).
    """
    applicable = [r for r in rules if framework in r.frameworks]
    findings: list[Finding] = [_to_finding(_evaluate_one(baseline, r)) for r in applicable]

    pass_count = sum(1 for f in findings if f.status == Status.PASS)
    fail_count = sum(1 for f in findings if f.status == Status.FAIL)
    unknown_count = sum(1 for f in findings if f.status == Status.UNKNOWN)
    determinable = pass_count + fail_count
    score_pct = round(pass_count / determinable * 100.0, 1) if determinable else None
    risk_level = _risk_level_from_findings(findings)

    return DeviceResult(
        device=device,
        framework=framework,
        score=score_pct,
        risk_level=risk_level,
        pass_count=pass_count,
        fail_count=fail_count,
        unknown_count=unknown_count,
        findings=findings,
        remediation=[],
        review_queue_count=0,
    )


def _sev(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.MEDIUM
