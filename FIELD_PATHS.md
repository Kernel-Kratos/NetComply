# Schema field paths and public API

Generated from `core/schema.py` (owner: P1). This is a reference for P2
(normalization) and P3 (rules). Every field path below is exactly what a rule
in `rules/*.yaml` references in its `field:` key (e.g.
`management.telnet_enabled`).

## Field paths (rule-reference format) with Python value type

All 20 leaves are `core.schema.FieldValue`, whose attributes are:

| FieldValue attribute | Python type | Meaning |
|---|---|---|
| `value` | `Any` (typed per field below) | The extracted value (`None` = not found / Unknown) |
| `source_line` | `str \| None` | The exact config line the value came from |
| `line_number` | `int \| None` | 1-based line number in the source block |
| `confidence` | `float` | 0.0–1.0 extraction confidence |
| `origin` | `Literal["mapping", "llm", "admin"]` | Where the value came from |

`set_field()` enforces that `value` matches the field's Python type. `None`
is always allowed (Unknown). `bool` is checked before `int` because `bool` is
a subclass of `int` in Python.

### device (identity)
| Field path | Python type of `.value` |
|---|---|
| `device.vendor` | `str` |
| `device.os` | `str` |
| `device.hostname` | `str` |
| `device.serial` | `str` |

### management
| Field path | Python type of `.value` |
|---|---|
| `management.telnet_enabled` | `bool` |
| `management.ssh_enabled` | `bool` |
| `management.ssh_version` | `int` |
| `management.http_server_enabled` | `bool` |
| `management.https_enabled` | `bool` |
| `management.idle_timeout_min` | `int` |

### authentication
| Field path | Python type of `.value` |
|---|---|
| `authentication.password_min_length` | `int` |
| `authentication.password_encryption` | `bool` |
| `authentication.aaa_enabled` | `bool` |

### logging
| Field path | Python type of `.value` |
|---|---|
| `logging.syslog_servers` | `list[str]` |
| `logging.admin_logging` | `bool` |

### snmp
| Field path | Python type of `.value` |
|---|---|
| `snmp.v1_v2_enabled` | `bool` |
| `snmp.default_community` | `bool` |

### time
| Field path | Python type of `.value` |
|---|---|
| `time.ntp_servers` | `list[str]` |

### crypto
| Field path | Python type of `.value` |
|---|---|
| `crypto.weak_ciphers_enabled` | `bool` |

### banner
| Field path | Python type of `.value` |
|---|---|
| `banner.login_banner_set` | `bool` |

Total: **20** leaf paths.

## Public API P2 uses to build a baseline

All in `core/schema.py` (owner: P1). `mappings.py` (P2) uses the same
`rule_paths()` to validate mapping targets.

### Set a field with evidence
```python
def set_field(
    baseline: SecurityBaseline,
    path: str,
    value: Any,
    *,
    source_line: str,
    line_number: int | None,
    confidence: float,
    origin: Literal["mapping", "llm", "admin"],
) -> None
```
`confidence` and `origin` are required keyword arguments. `source_line` is
required when `value is not None` (empty `source_line` raises `ValueError`).
Validates `path` against `valid_paths()` and enforces that `value`'s type
matches the field (see table above). Raises `ValueError` on any violation.

Usage:
```python
from core.schema import SecurityBaseline, set_field
b = SecurityBaseline()
set_field(b, "management.ssh_version", 2,
          source_line="ip ssh version 2", line_number=7,
          confidence=0.93, origin="mapping")
```

Direct attribute assignment also works (the `FieldValue` is a plain pydantic
model), but `set_field()` is the validated entry point:
```python
b.management.ssh_version = FieldValue(value=2, source_line=..., ...)
```

### Validate a path
```python
def is_valid_path(path: str) -> bool
```
Returns `True` if `path` is one of the 20 rule-referenced field paths.

### List valid paths (rules + device identity)
```python
def valid_paths() -> set[str]
```
Returns the set of all 20 dotted field paths.

### List rule paths (excludes device.*)
```python
def rule_paths() -> set[str]
```
Returns every path except `device.*` (identity comes from `core/ingest.py`,
P2). Used by `compliance.load_rules()` to reject rules with invalid fields,
and by `mappings.py` (P2) to validate mapping targets.

### Get a field
```python
def get_field(baseline: SecurityBaseline, path: str) -> FieldValue
```
Returns the `FieldValue` at `path`. Raises `ValueError` on invalid path.

### Baseline construction
```python
b = SecurityBaseline()   # all leaves start as value=None (Unknown)
```
`None` means "not found" (Unknown); `False` means explicitly disabled. Never
conflate the two (AGENTS.md principle #2).

## Golden JSON shape

`baseline.model_dump()` produces the golden JSON used by tests. One example
leaf (as it appears in `model_dump()` output):

```json
{
  "management": {
    "ssh_version": {
      "value": 2,
      "source_line": "ip ssh version 2",
      "line_number": 7,
      "confidence": 0.93,
      "origin": "mapping"
    }
  }
}
```

The full dump is recursive: `{"device": {...}, "management": {...}, ...}` with
every leaf as the 5-key object above.

## Comparison against AGENTS.md section 5

AGENTS.md §5 gives this example normalized JSON:

```json
{
  "device": {"vendor", "os", "hostname", "serial"},
  "management": {"telnet_enabled", "ssh_enabled", "ssh_version",
                 "http_server_enabled", "https_enabled", "idle_timeout_min"},
  "authentication": {"password_min_length", "password_encryption", "aaa_enabled"},
  "logging": {"syslog_servers", "admin_logging"},
  "snmp": {"v1_v2_enabled", "default_community"},
  "time": {"ntp_servers"},
  "crypto": {"weak_ciphers_enabled"},
  "banner": {"login_banner_set"}
}
```

Every path in the AGENTS.md example exists in `core/schema.py`. **No field-path
differences.**

The schema rules (§5) require:
- Evidence on every value (`source_line`, `line_number`, `confidence`,
  `origin`). ✓ `FieldValue` carries all four; `set_field()` populates them.
- `null` = not found, `false` = explicitly disabled. ✓
- Adding a field means updating schema + at least one rule (or documented
  reason) + LLM prompt field list + golden tests. ✓ schema is the SSOT.

### Fields with NO rule (initial checks)
Per AGENTS.md §5, every field needs at least one rule or a documented reason
it has none (P3's `rules/cis.yaml` work). Fields with no rule:

- `management.ssh_enabled`
- `management.https_enabled`
- `authentication.aaa_enabled`
- `logging.admin_logging`
- `crypto.weak_ciphers_enabled`
- `device.*` (all four: vendor, os, hostname, serial — populated by ingest)

`snmp.default_community` **IS** in the initial checks and should have a rule.

### Observations / action items
1. **Initial scope vs. schema size.** AGENTS.md §5 scopes the first build to
   about 10–12 checks. The schema defines 20 leaves; the 6 above have no
   rule yet. P3 must add rules or document a reason for each.
2. Device identity fields (`device.*`) are populated by `core/ingest.py`
   (P2), not by rules.
