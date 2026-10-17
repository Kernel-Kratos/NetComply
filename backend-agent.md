# Backend Agent: NetComply AI

You are the **backend agent**. You own everything that parses, judges, stores, and reports. Read `AGENTS.md` first; its principles apply to you in full.

## You own

- `core/`: ingest, redact, schema, normalize, mappings, compliance, remediation, report, service
- `core/llm/client.py`: the only module allowed to call a model
- `rules/`, `templates/remediation/`, `samples/`
- `tests/` for all of the above
- `.env.example`

## You must not touch

- `app/` (frontend agent's territory). If the UI needs something, expose it through `core/service.py` instead.

## The contract with the frontend

The frontend calls only `core/service.py`. Keep these signatures stable. Types live in `core/contracts.py` (pydantic).

| Function | Returns |
|---|---|
| `audit_files(files, framework)` | `list[DeviceResult]` |
| `get_review_queue(device_id)` | `list[UnmappedLine]` |
| `suggest_mapping(line)` | `MappingSuggestion` (LLM suggestion only, not saved) |
| `save_mapping(mapping)` | `None` (admin-approved only) |
| `reaudit(device_ids, framework)` | `list[DeviceResult]` |
| `generate_report(device_id)` | `bytes` (PDF) |
| `list_frameworks()` | `list[str]` |
| `llm_status()` | `LLMStatus` (backend, model, offline, ready) |

`DeviceResult` includes: device identity, score, risk level, findings (each Pass/Fail/Unknown with severity, framework refs, `source_line`, `line_number`), unknown count, and remediation blocks.

**Changing a signature or type breaks the frontend.** Describe the change in your PR and update the shape in `app/mock_service.py`'s docstring so the frontend agent can follow.

## The Gemma 4 plug-in point

All model access goes through `core/llm/client.py`. To go live, a human edits `.env`:

```
LLM_BACKEND=openai_compat
LLM_BASE_URL=<endpoint>
LLM_MODEL=<gemma 4 model id>
LLM_API_KEY=<key if needed>
```

Rules for you:

- **Never** import a model SDK or call a model URL outside `client.py`. Use `LLMClient().complete_json(system, user)`.
- Do not hardcode a model name, URL, or key anywhere. Read config via `load_config()`.
- The default backend is `mock`, so the full pipeline and every test must work with no key and no network.
- If a different provider needs a non-OpenAI-style API, add a new backend branch in `client.py`. Do not leak provider details into other modules.
- Do not assume Gemma 4's JSON reliability. `complete_json` retries once, and callers send anything still invalid to the review queue.
- `OFFLINE=1` must reject non-local endpoints at startup. Keep that check.
- Redact before calling the client. The client does not redact for you.

## Extraction format

The normalizer asks the model for `{"extractions": [{"field", "value", "source_line", "confidence"}]}`. After parsing:

1. Validate fields against `core/schema.py`.
2. Reject any item whose `source_line` is not present in the input block.
3. Fill in `line_number` yourself. Do not trust the model for it.
4. Items below `CONFIDENCE_THRESHOLD` go to the review queue.

## Priorities (in order)

1. `schema.py` + `contracts.py` + `service.py` skeleton, so the frontend can integrate early
2. `redact.py` with tests
3. `ingest.py` and the mock-backed `normalize.py` for Cisco IOS
4. `compliance.py` + `rules/cis.yaml` (about 10 checks)
5. `mappings.py` (SQLite) and the training loop
6. `remediation.py` templates, then `report.py`
7. Juniper and MikroTik samples; test the "unseen vendor" flow

## Definition of done

- `pytest -q` passes with `LLM_BACKEND=mock`
- Golden JSON exists for every file in `samples/`
- A test proves known secrets never appear in a captured prompt
- Switching to a real model requires only `.env` edits
- No `eval`/`exec`; rules are data

## Multi-person setup

Five people work on five devices. Read `TEAM.md`. The backend is split across P1, P2, P3 and P5, so **edit only the files your person owns** there. `core/report.py` belongs to P5, not the backend lead. If you need a change in a file you do not own, say which owner to ask.
