# AGENTS.md: NetComply AI

Guidance for AI coding agents working in this repository. Read this fully before making changes.

## 1. What this project is

NetComply AI is a vendor-agnostic network compliance engine. It ingests configuration files from any network device (Cisco, Juniper, Palo Alto, MikroTik, and others), converts them into one vendor-neutral JSON model, checks that model against security frameworks (CIS, NIST SP 800-53, DISA STIG, ISO/IEC 27001), and produces a per-device PDF report with pass/fail findings and remediation commands.

Tagline: *Any vendor. Any config. One source of truth for security compliance.*

**Core idea: an LLM understands, rules judge, evidence proves.**

- The LLM interprets unfamiliar config syntax and drafts remediation text.
- Deterministic YAML rules decide Pass / Fail / Unknown.
- Every finding points to the exact config line it came from.

## 2. Non-negotiable principles

These override convenience. If a task seems to conflict with one, stop and flag it instead of working around it.

1. **The LLM never decides compliance.** Pass/Fail/Unknown comes only from the rules engine reading the normalized model. Never ask the LLM "is this device compliant?"
2. **Three states, not two.** A missing value is `null` (Unknown), not `false`. The report must never claim a pass it could not verify.
3. **Evidence on every value.** Each extracted field carries `source_line`, `line_number`, `confidence`, and `origin` (`mapping`, `llm`, or `admin`).
4. **Redact before any model call.** Secrets (password hashes, pre-shared keys, SNMP communities, private keys, API tokens) must be stripped before text reaches any LLM, local or remote.
5. **Offline-first.** Production mode makes no outbound network calls. Configs never leave the machine. See section 8.
6. **No silent guessing.** Low-confidence or unmapped lines go to the review queue, not into the model as best guesses.
7. **Learning is admin-approved.** LLM suggestions are not saved as mappings until an admin accepts them in the training GUI.
8. **Remediation is advice.** Every generated command block is labeled "Suggested. Review and test before applying."
9. **No `eval()` / `exec()`** on rules, config text, or model output. Ever.

## 3. Pipeline

```
Upload (single/bulk)
  -> Ingest & preprocess   detect vendor/OS, split into blocks, redact secrets
  -> Normalize             1) learned-mapping lookup  2) LLM extraction  3) review queue
  -> Security Baseline Model (vendor-neutral JSON)
  -> Compliance engine     YAML rules -> Pass / Fail / Unknown + severity
  -> Remediation           templates first, LLM for gaps
  -> PDF report            one per device

Side loop: review queue -> training GUI -> saved mappings -> used by Normalize next time
```

## 4. Repository layout

```
netcomply/
  app/                      Streamlit UI
    main.py
    pages/                  Upload, Dashboard, Device, Training
  core/
    ingest.py               file loading, vendor/OS detection, block splitting
    redact.py               secret redaction (pure functions, heavily tested)
    schema.py               pydantic models for the Security Baseline Model
    normalize.py            mapping lookup -> LLM extraction -> review queue
    mappings.py             learned-mapping store (SQLite)
    compliance.py           rule loader + evaluator
    remediation.py          template lookup + LLM fallback
    report.py               ReportLab PDF generation
    llm/
      client.py             backend interface (local | api), the only place that calls a model
      prompts/              prompt templates as files, versioned
  rules/                    one YAML file per framework (cis.yaml, nist.yaml, ...)
  templates/remediation/    per-vendor fix templates, keyed by remediation id
  samples/                  sample configs (cisco_ios, juniper, mikrotik)
  tests/
  docs/architecture.md      2-page architecture doc (a deliverable)
  README.md                 setup instructions (a deliverable)
  AGENTS.md
```

If the layout drifts from this, update this file in the same change.

## 5. The Security Baseline Model

One neutral JSON per device, grouped by category so frameworks map onto it:

```json
{
  "device": {"vendor": "cisco", "os": "IOS 15.2", "hostname": "SW1", "serial": "FOC1234"},
  "management": {"telnet_enabled": false, "ssh_enabled": true, "ssh_version": 2,
                 "http_server_enabled": true, "https_enabled": true, "idle_timeout_min": 10},
  "authentication": {"password_min_length": null, "password_encryption": true, "aaa_enabled": true},
  "logging": {"syslog_servers": ["10.0.0.5"], "admin_logging": true},
  "snmp": {"v1_v2_enabled": true, "default_community": true},
  "time": {"ntp_servers": ["10.0.0.1"]},
  "crypto": {"weak_ciphers_enabled": false},
  "banner": {"login_banner_set": false}
}
```

Rules for the schema:

- Defined in `core/schema.py` with pydantic. This is the single source of truth; do not scatter field names as string literals.
- Each leaf is stored with its evidence: `{value, source_line, line_number, confidence, origin}`.
- `null` means not found. `false` means explicitly disabled. Never conflate them.
- Adding a field means updating: schema, at least one rule or a documented reason it has none, LLM prompt field list, and golden tests.
- Initial scope is about 10 to 12 checks: Telnet, SSH version, HTTP management, SNMP defaults, logging, NTP, idle timeout, login banner, password policy, password encryption.

## 6. Normalization

Order of resolution for each config block:

1. **Mapping lookup** in the learned-mappings store (SQLite). Fast, free, deterministic. Prefer this.
2. **LLM extraction** for anything unmatched. The LLM receives the schema field list, a few matching few-shot examples from the mapping store, and the redacted block. It must return JSON only:
   ```json
   {"field": "management.ssh_version", "value": 2, "source_line": "ip ssh version 2", "confidence": 0.93}
   ```
3. **Review queue** for confidence below `CONFIDENCE_THRESHOLD` (default 0.7), invalid output, or unmapped lines.

LLM output handling:

- Validate every response against the pydantic schema. On failure, retry once, then send to the review queue. Never patch up malformed output by guessing.
- Reject any extracted value whose `source_line` does not actually appear in the input block. This catches hallucinated evidence.
- Chunk by config block (interface, line vty, ssh settings, etc.). Never send an entire file in one call.
- Temperature 0 (or the lowest the backend allows) for extraction.

## 7. Training loop (dynamic adaptation)

- The Training page lists unrecognized raw lines from the review queue, with an LLM-suggested mapping prefilled (suggestion only).
- The admin accepts or edits it: target schema field, and how to capture the value.
- Accepted mappings are stored in SQLite:
  `mappings(id, vendor, os_pattern, line_regex, target_field, value_capture, created_by, created_at, active)`
- Stored mappings are used for direct matching (Normalize step 1) and as few-shot examples in later prompts.
- No model retraining, no code redeploy. "Learning" means a growing store of admin-verified mappings.
- After saving, the app re-runs normalization and re-audit for the affected devices.

## 8. LLM backend and privacy

All model calls go through `core/llm/client.py`. No other module imports a model SDK or makes HTTP calls to one.

Configuration (environment variables):

| Variable | Meaning | Default |
|---|---|---|
| `LLM_BACKEND` | `mock` (canned output, default) or `openai_compat` (any /chat/completions server) | `mock` |
| `LLM_MODEL` | Model identifier, e.g. a Gemma 4 variant | none, must be set |
| `LLM_BASE_URL` | Endpoint of the local model server | `http://localhost:11434` |
| `OFFLINE` | `1` blocks any non-local backend and any non-localhost network call | `1` |
| `CONFIDENCE_THRESHOLD` | Minimum confidence to auto-accept an extraction | `0.7` |

Rules:

- Do not hardcode a model name. The target model is Gemma 4, but verify its actual features (context length, JSON/tool-calling reliability) against the provider docs and do not assume them.
- If `OFFLINE=1` and `LLM_BACKEND=openai_compat`, the client must raise an error at startup, not warn.
- `redact()` must run on every payload before it reaches the client. Add a test that asserts known secrets never appear in a captured prompt.
- Log prompts and responses locally for debugging, but only the redacted versions.

## 9. Compliance rules

Rules live in `rules/*.yaml` as data, not code. Adding a framework or control must not require changing Python.

```yaml
- id: CIS-MGMT-01
  title: Telnet must be disabled
  frameworks: {CIS: "1.1.1", NIST: "AC-17", STIG: "V-0000"}
  field: management.telnet_enabled
  op: eq
  value: false
  severity: high            # low | medium | high | critical
  remediation: disable_telnet
```

- Supported `op` values are a small, closed set (`eq`, `ne`, `gte`, `lte`, `in`, `not_in`, `exists`, `empty`). Implement them as plain functions in `compliance.py`. Do not evaluate expression strings.
- Evaluation returns `pass`, `fail`, or `unknown` (when the field is `null`).
- One control can reference several frameworks. The user selects a framework and gets the relevant subset.
- Do not invent framework control IDs. If a real ID is not known, leave it as a clearly marked placeholder and note it in the PR.
- Scoring: `score = pass / (pass + fail) * 100`, rounded to 1 decimal; `None` when `pass + fail == 0`. `unknown` is reported separately and never counted as a pass.

## 10. Remediation

- Look up `rules[*].remediation` in `templates/remediation/<vendor>.yaml` first. Templates are the ground truth for common fixes.
- Use the LLM only when no template exists for that vendor and OS. Pass the vendor, OS version, and remediation id.
- Output is an ordered list of CLI commands in that vendor's syntax.
- Always attach the label: "Suggested. Review and test before applying."
- Never execute commands against a device. This tool reads and reports only.

## 11. PDF report

One PDF per device (ReportLab), containing:

1. Device identification: vendor, model, OS version, hostname, serial number where available.
2. Score summary and risk level, with unknown count shown separately.
3. Findings table: control, framework reference, Pass/Fail/Unknown, severity, source line as evidence.
4. Remediation steps per failed control, in that vendor's syntax.

Keep generation deterministic. The same input must produce the same report content.

## 12. Setup and commands

Python 3.11+. Adjust if the repo's actual tooling differs, and update this section when it does.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export LLM_BACKEND=local
export LLM_MODEL=<your-model-id>
export OFFLINE=1

streamlit run app/main.py        # run the app
pytest -q                        # run tests
ruff check . && ruff format .    # lint and format
```

## 13. Testing requirements

- **Golden tests:** each file in `samples/` has an expected normalized JSON. Normalization changes must keep these passing or update them deliberately.
- **Rules engine:** unit test every operator and the three result states, including `null` -> unknown.
- **Redaction:** table-driven tests per vendor for each secret type. A leaked secret is a release blocker.
- **LLM client:** mocked in tests. Tests must never call a real model or the network.
- **Malformed model output:** test invalid JSON, wrong field names, and fabricated `source_line` values. All must end in the review queue.
- Any bug fix gets a regression test.

## 14. Code conventions

- Type hints everywhere. pydantic for data crossing module boundaries.
- Small pure functions in `core/`. Keep Streamlit code thin, with no business logic in `app/`.
- Prompts are files in `core/llm/prompts/`, not inline strings. Version them (`extract_v1.txt`).
- Fail loudly on unexpected state. Do not swallow exceptions around parsing or model calls.
- No new dependencies without a reason noted in the PR. Prefer the standard library.

## 15. Scope

**In scope for the current build:** 2 to 3 vendors (Cisco IOS, Juniper, MikroTik as the "unseen vendor" demo), about 10 checks, CIS mapping with the YAML format ready for more frameworks, the training loop, the Streamlit dashboard, and per-device PDF reports.

**Out of scope for now (roadmap only):** cloud security groups (AWS/Azure), SONiC, full CIS/NIST/STIG coverage, live collection via Netmiko/NAPALM, screenshot ingestion. Do not start these without being asked.

## 16. Deliverables (keep in sync)

- Source code repo with a README containing setup instructions
- Architecture document, max 2 pages (`docs/architecture.md`)
- Demo video, max 2 minutes
- Technical presentation, max 5 slides
- Sample configs for each supported vendor in `samples/`

## 17. When unsure

Ask, or leave a clearly marked `TODO(agent):` with the question. Do not guess at security-relevant behavior: redaction patterns, rule thresholds, framework control IDs, or remediation commands.

## 18. Agent roles

Work is split between two agents with separate file ownership. Read your role file before starting.

- `agents/backend-agent.md`: owns `core/`, `rules/`, `templates/`, tests, and the LLM client.
- `agents/frontend-agent.md`: owns `app/` and the mock service.

They meet only at `core/service.py` and `core/contracts.py`. To connect Gemma 4, edit `.env` (see `.env.example`). No code changes are needed.

## 19. Team setup

The project is built by five people on five devices. See `TEAM.md` for ownership, device setup, LLM modes, and git workflow, and `FILES.md` for a guide to every file. Edit only files owned by the person you are working for.
