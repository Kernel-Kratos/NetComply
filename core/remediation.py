"""Remediation engine: template-first, LLM fallback for gaps.

Owner: P3. Looks up rules[*].remediation in templates/remediation/<vendor>.yaml
first. Uses the LLM only when no template exists for that vendor/OS. Never
executes commands against a device. Every block carries the disclaimer.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from core.contracts import DISCLAIMER, DeviceInfo, Finding, RemediationBlock
from core.llm.client import LLMClient

TEMPLATES_DIR = Path("templates/remediation")


def _load_vendor_templates(vendor: str) -> dict[str, dict[str, Any]]:
    """Load all remediation templates for a vendor. Returns {} if missing."""
    path = TEMPLATES_DIR / f"{vendor}.yaml"
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        return {}
    return data


def _template_block(rule_id: str, vendor: str, templates: dict[str, Any]) -> RemediationBlock | None:
    """Build a RemediationBlock from a template, or None if no template exists."""
    entry = templates.get(rule_id)
    if not entry:
        return None
    commands = entry.get("commands", [])
    if not isinstance(commands, list):
        commands = []
    clean_commands = [c.split("#")[0].rstrip() for c in commands if c.strip()]
    return RemediationBlock(
        rule_id=rule_id,
        vendor=vendor,
        commands=clean_commands,
        source="template",
        disclaimer=DISCLAIMER,
    )


def _llm_block(rule_id: str, vendor: str, os_version: str | None, finding: Finding) -> RemediationBlock:
    """Ask the LLM for remediation commands when no template exists."""
    client = LLMClient()
    system = (
        "You are a network security engineer. Return JSON only: "
        '{"commands": ["cmd1", "cmd2"]}. Use the vendor\'s CLI syntax.'
    )
    user = (
        f"Vendor: {vendor}\n"
        f"OS: {os_version or 'unknown'}\n"
        f"Rule: {rule_id} - {finding.title}\n"
        f"Field: {finding.field}\n"
        f"Observed value: {finding.observed_value}\n"
        "Provide ordered CLI commands to remediate this finding."
    )
    try:
        data = client.complete_json(system, user)
        commands = data.get("commands", [])
        if not isinstance(commands, list):
            commands = []
    except Exception:
        commands = []
    return RemediationBlock(
        rule_id=rule_id,
        vendor=vendor,
        commands=[str(c) for c in commands],
        source="llm",
        disclaimer=DISCLAIMER,
    )


def build_remediation(
    device: DeviceInfo,
    findings: list[Finding],
) -> list[RemediationBlock]:
    """Build remediation blocks for findings.

    Templates first; LLM fallback when no template exists for the vendor/rule.
    Never executes commands. Called by core/service.py with (device, findings).
    """
    templates = _load_vendor_templates(device.vendor)
    blocks: list[RemediationBlock] = []
    for finding in findings:
        block = _template_block(finding.rule_id, device.vendor, templates)
        if block is None:
            block = _llm_block(finding.rule_id, device.vendor, device.os_version, finding)
        blocks.append(block)
    return blocks
