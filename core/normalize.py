"""Normalization engine: Mapping lookup -> LLM extraction -> Review queue. Owner: P2."""
from __future__ import annotations

import os
import re
from pathlib import Path

from core.contracts import UnmappedLine
from core.ingest import ConfigBlock, IngestedDevice
from core.llm.client import LLMClient, LLMError
from core.mappings import lookup_mapping
from core.schema import SecurityBaseline, is_valid_path, rule_paths, set_field

CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.7"))
PROMPT_PATH = Path("core/llm/prompts/extract_v1.txt")


def _load_prompt_template() -> str:
    if PROMPT_PATH.exists():
        return PROMPT_PATH.read_text(encoding="utf-8")
    # Default fallback prompt if text file isn't created yet
    return (
        "You are a network configuration analyzer. Extract compliance values into JSON format.\n"
        "Valid fields: {valid_fields}\n"
        "Return a JSON object with a key 'extractions' containing a list of objects: "
        "[{{'field': str, 'value': any, 'source_line': str, 'confidence': float}}]."
    )


def normalize_device(ingested: IngestedDevice) -> tuple[SecurityBaseline, list[UnmappedLine]]:
    baseline = SecurityBaseline()
    
    # Populate device identity (device.*) handled by ingest, not rules
    set_field(baseline, "device.vendor", ingested.device.vendor, source_line=ingested.device.filename, line_number=1, confidence=1.0, origin="mapping")
    if ingested.device.os_version:
        set_field(baseline, "device.os", ingested.device.os_version, source_line=ingested.device.filename, line_number=1, confidence=1.0, origin="mapping")
    if ingested.device.hostname:
        set_field(baseline, "device.hostname", ingested.device.hostname, source_line=ingested.device.filename, line_number=1, confidence=1.0, origin="mapping")
    if ingested.device.serial:
        set_field(baseline, "device.serial", ingested.device.serial, source_line=ingested.device.filename, line_number=1, confidence=1.0, origin="mapping")

    review_queue: list[UnmappedLine] = []
    client = LLMClient()
    prompt_template = _load_prompt_template()
    valid_fields_str = ", ".join(sorted(rule_paths()))

    for block in ingested.blocks:
        for config_line in block.lines:
            raw_ln = config_line.raw.strip()
            if not raw_ln or raw_ln.startswith(("!", "#")):
                continue

            # Step 1: Learned mapping lookup
            match = lookup_mapping(ingested.device.vendor, raw_ln)
            if match:
                val = _coerce_value(match["target_field"], match.get("value_capture") or raw_ln)
                try:
                    set_field(
                        baseline,
                        match["target_field"],
                        val,
                        source_line=config_line.raw,
                        line_number=config_line.line_number,
                        confidence=1.0,
                        origin="mapping",
                    )
                    continue
                except ValueError:
                    pass  # Fall through to LLM/review if coercion fails

            # Step 2: LLM extraction for unmatched/complex lines
            try:
                system_prompt = prompt_template.format(valid_fields=valid_fields_str)
                user_prompt = f"Vendor: {ingested.device.vendor}\nBlock Header: {block.header}\nLine: {config_line.redacted}"
                
                resp = client.complete_json(system_prompt, user_prompt)
                extractions = resp.get("extractions", [])

                extracted_for_line = False
                for ext in extractions:
                    field = ext.get("field")
                    val = ext.get("value")
                    src = ext.get("source_line", "")
                    conf = float(ext.get("confidence", 0.0))

                    # Guardrails from AGENTS.md & backend-agent.md
                    if not is_valid_path(field) or field not in rule_paths():
                        continue
                    # Anti-hallucination: source_line must actually exist in the block text
                    if src not in block.redacted_text and src not in block.header:
                        continue
                    if conf < CONFIDENCE_THRESHOLD:
                        continue

                    try:
                        set_field(
                            baseline,
                            field,
                            val,
                            source_line=config_line.raw,
                            line_number=config_line.line_number,
                            confidence=conf,
                            origin="llm",
                        )
                        extracted_for_line = True
                    except ValueError:
                        continue

                if not extracted_for_line and len(raw_ln) > 3:
                    # Send to review queue if high-entropy line wasn't matched
                    review_queue.append(
                        UnmappedLine(
                            device_id=ingested.device.device_id,
                            line_number=config_line.line_number,
                            raw_line=config_line.raw,
                            block_context=block.redacted_text,
                        )
                    )

            except (LLMError, Exception):
                # On LLM failure, route line to review queue rather than crashing
                review_queue.append(
                    UnmappedLine(
                        device_id=ingested.device.device_id,
                        line_number=config_line.line_number,
                        raw_line=config_line.raw,
                        block_context=block.redacted_text,
                    )
                )

    return baseline, review_queue


def _coerce_value(field: str, capture: str) -> any:
    """Helper to convert raw captured strings into appropriate Python types per field."""
    if "enabled" in field or "encryption" in field:
        return not ("disable" in capture.lower() or "false" in capture.lower() or "no " in capture.lower())
    if "version" in field or "timeout" in field or "length" in field:
        m = re.search(r"\d+", capture)
        return int(m.group(0)) if m else capture
    return capture