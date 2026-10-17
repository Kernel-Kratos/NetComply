"""Security Baseline Model: vendor-neutral normalized device config.

Owner: P1. This is the single source of truth for field names. Adding a field
means updating here, at least one rule, the LLM prompt field list, and golden
tests (AGENTS.md section 5).

Every leaf is a FieldValue carrying {value, source_line, line_number,
confidence, origin}.  ``null`` (value None) means not found (Unknown); it is
never conflated with an explicit false.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class FieldValue(BaseModel):
    """A single extracted leaf with its supporting evidence."""

    value: Any = None
    source_line: str | None = None
    line_number: int | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    origin: Literal["mapping", "llm", "admin"] = "llm"


class DeviceCategory(BaseModel):
    vendor: FieldValue = FieldValue()
    os: FieldValue = FieldValue()
    hostname: FieldValue = FieldValue()
    serial: FieldValue = FieldValue()


class Management(BaseModel):
    telnet_enabled: FieldValue = FieldValue()
    ssh_enabled: FieldValue = FieldValue()
    ssh_version: FieldValue = FieldValue()
    http_server_enabled: FieldValue = FieldValue()
    https_enabled: FieldValue = FieldValue()
    idle_timeout_min: FieldValue = FieldValue()


class Authentication(BaseModel):
    password_min_length: FieldValue = FieldValue()
    password_encryption: FieldValue = FieldValue()
    aaa_enabled: FieldValue = FieldValue()


class Logging(BaseModel):
    syslog_servers: FieldValue = FieldValue()
    admin_logging: FieldValue = FieldValue()


class Snmp(BaseModel):
    v1_v2_enabled: FieldValue = FieldValue()
    default_community: FieldValue = FieldValue()


class Time(BaseModel):
    ntp_servers: FieldValue = FieldValue()


class Crypto(BaseModel):
    weak_ciphers_enabled: FieldValue = FieldValue()


class Banner(BaseModel):
    login_banner_set: FieldValue = FieldValue()


class SecurityBaseline(BaseModel):
    """One normalized model per device."""

    device: DeviceCategory = DeviceCategory()
    management: Management = Management()
    authentication: Authentication = Authentication()
    logging: Logging = Logging()
    snmp: Snmp = Snmp()
    time: Time = Time()
    crypto: Crypto = Crypto()
    banner: Banner = Banner()


# Expected Python type of each leaf's ``value``.  ``None`` (Unknown) is always
# allowed regardless of type.  list[str] fields are marked with the marker
# object below and validated element-wise.
_LIST_STR = object()

_VALUE_TYPES: dict[str, Any] = {
    "device.vendor": str,
    "device.os": str,
    "device.hostname": str,
    "device.serial": str,
    "management.telnet_enabled": bool,
    "management.ssh_enabled": bool,
    "management.ssh_version": int,
    "management.http_server_enabled": bool,
    "management.https_enabled": bool,
    "management.idle_timeout_min": int,
    "authentication.password_min_length": int,
    "authentication.password_encryption": bool,
    "authentication.aaa_enabled": bool,
    "logging.syslog_servers": _LIST_STR,
    "logging.admin_logging": bool,
    "snmp.v1_v2_enabled": bool,
    "snmp.default_community": bool,
    "time.ntp_servers": _LIST_STR,
    "crypto.weak_ciphers_enabled": bool,
    "banner.login_banner_set": bool,
}


def valid_paths() -> set[str]:
    """Return every dotted field path a rule may reference (the FieldValue leaves).

    Example: {"management.telnet_enabled", "management.ssh_version", ...}.
    """
    paths: set[str] = set()

    def walk(node: BaseModel, prefix: str = "") -> None:
        for name in type(node).model_fields:
            path = f"{prefix}.{name}" if prefix else name
            value = getattr(node, name)
            if isinstance(value, FieldValue):
                paths.add(path)
            elif isinstance(value, BaseModel):
                walk(value, path)

    walk(SecurityBaseline())
    return paths


def rule_paths() -> set[str]:
    """Return every field path except ``device.*`` identity fields.

    Rules and mappings reference these; device identity comes from ingest.
    """
    return {p for p in valid_paths() if not p.startswith("device.")}


def is_valid_path(path: str) -> bool:
    """Return True if ``path`` is a valid rule-referenced field path."""
    return path in valid_paths()


def _check_type(path: str, value: Any) -> None:
    """Raise ValueError if ``value``'s type does not match ``path``'s type.

    None is always allowed (Unknown).
    """
    if value is None:
        return
    expected = _VALUE_TYPES.get(path)
    if expected is None:
        raise ValueError(f"Invalid schema path: {path}")
    if expected is _LIST_STR:
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ValueError(
                f"Path {path} expects list[str], got {type(value).__name__}"
            )
        return
    # bool must be checked before int because bool is a subclass of int.
    if expected is bool:
        if not isinstance(value, bool):
            raise ValueError(
                f"Path {path} expects bool, got {type(value).__name__}"
            )
        return
    if expected is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"Path {path} expects int, got {type(value).__name__}"
            )
        return
    if expected is str:
        if not isinstance(value, str):
            raise ValueError(
                f"Path {path} expects str, got {type(value).__name__}"
            )
        return
    raise ValueError(f"Path {path} has unsupported expected type {expected!r}")


def set_field(
    baseline: SecurityBaseline,
    path: str,
    value: Any,
    *,
    source_line: str,
    line_number: int | None,
    confidence: float,
    origin: Literal["mapping", "llm", "admin"],
) -> None:
    """Set a leaf field with evidence, validating the path and value type first.

    P2 uses this to populate a baseline from mapping/extraction results.
    Raises ValueError if ``path`` is not a valid schema path, if ``value``'s
    type does not match the field, or if ``value`` is not None and
    ``source_line`` is empty.
    """
    if path not in valid_paths():
        raise ValueError(f"Invalid schema path: {path}")
    if value is not None and not source_line:
        raise ValueError(
            f"source_line is required when value is not None (path {path})"
        )
    _check_type(path, value)
    node: Any = baseline
    parts = path.split(".")
    for part in parts[:-1]:
        node = getattr(node, part)
    leaf = getattr(node, parts[-1])
    if not isinstance(leaf, FieldValue):
        raise ValueError(f"Path {path} is not a FieldValue leaf")
    setattr(
        node,
        parts[-1],
        FieldValue(
            value=value,
            source_line=source_line,
            line_number=line_number,
            confidence=confidence,
            origin=origin,
        ),
    )


def get_field(baseline: SecurityBaseline, path: str) -> FieldValue:
    """Return the FieldValue at ``path``.

    Raises ValueError if ``path`` is not a valid schema path.
    """
    if path not in valid_paths():
        raise ValueError(f"Invalid schema path: {path}")
    node: Any = baseline
    for part in path.split("."):
        node = getattr(node, part)
    if not isinstance(node, FieldValue):
        raise ValueError(f"Path {path} is not a FieldValue leaf")
    return node
