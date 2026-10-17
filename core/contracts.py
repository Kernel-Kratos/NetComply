"""Shared contract between frontend and backend.

Owner: P1. This file is the sync point between five devices.
Change it ONLY through a PR labeled `contract`, approved by P1, and tell P4
so app/mock_service.py can follow. Bump CONTRACT_VERSION on every change.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

CONTRACT_VERSION = "1.0"
DISCLAIMER = "Suggested. Review and test before applying."


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"  # value not found: never treat as pass


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UploadedFile(BaseModel):
    filename: str
    content: bytes


class DeviceInfo(BaseModel):
    device_id: str
    filename: str
    vendor: str = "unknown"
    model: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    serial: str | None = None


class Evidence(BaseModel):
    source_line: str
    line_number: int | None = None
    confidence: float = Field(ge=0, le=1)
    origin: Literal["mapping", "llm", "admin"]


class Finding(BaseModel):
    rule_id: str
    title: str
    frameworks: dict[str, str] = {}  # e.g. {"CIS": "1.1.1", "NIST": "AC-17"}
    status: Status
    severity: Severity
    field: str  # schema path, e.g. "management.telnet_enabled"
    observed_value: Any | None = None
    evidence: Evidence | None = None  # None when status is UNKNOWN


class RemediationBlock(BaseModel):
    rule_id: str
    vendor: str
    commands: list[str]
    source: Literal["template", "llm"]
    disclaimer: str = DISCLAIMER


class DeviceResult(BaseModel):
    device: DeviceInfo
    framework: str
    score: float | None = None  # % of determinable controls passed; None if nothing determinable
    risk_level: Severity = Severity.LOW
    pass_count: int = 0
    fail_count: int = 0
    unknown_count: int = 0  # reported separately, never counted as pass
    findings: list[Finding] = []
    remediation: list[RemediationBlock] = []
    review_queue_count: int = 0


class UnmappedLine(BaseModel):
    device_id: str
    line_number: int
    raw_line: str
    block_context: str = ""  # surrounding lines, already redacted


class MappingSuggestion(BaseModel):
    """LLM suggestion only. Not saved until an admin accepts it."""
    target_field: str | None = None
    value_capture: str | None = None
    confidence: float = Field(default=0.0, ge=0, le=1)
    rationale: str = ""


class MappingIn(BaseModel):
    """An admin-approved mapping to store."""
    vendor: str
    os_pattern: str | None = None
    line_regex: str
    target_field: str
    value_capture: str | None = None
    created_by: str = "admin"


class LLMStatus(BaseModel):
    backend: str
    model: str
    offline_mode: bool
    ready: bool
