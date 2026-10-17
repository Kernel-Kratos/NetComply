# FILES.md: Guide to Every File

**Status:** `Ready` = already in the repo. `To build` = someone creates it. Owners are in `TEAM.md`.

## Root

| File | What it is | Owner | Status |
|---|---|---|---|
| `AGENTS.md` | Project-wide rules for AI coding agents: principles, pipeline, schema, rules format | P1 | Ready |
| `TEAM.md` | Who owns what, device setup, LLM modes, git workflow, plan | P1 | Ready |
| `FILES.md` | This guide | P1 | Ready |
| `README.md` | Setup instructions and project overview (a graded deliverable) | P5 | To build |
| `.env.example` | Template for per-device config, including the Gemma 4 plug-in settings | P2 | Ready |
| `.env` | Your own copy of the above. Never committed | each person | Local only |
| `requirements.txt` | Python dependencies, grouped by owner | P1 | Ready |
| `pytest.ini` | Makes `core` importable in tests, sets the test folder | P1 | Ready |
| `.gitignore` | Keeps secrets, databases, and real configs out of git | P1 | Ready |
| `.github/CODEOWNERS` | Maps folders to owners. Replace `@p1`..`@p5` with usernames | P1 | Ready |
| `.github/workflows/ci.yml` | CI: install, ruff check, pytest with mock backend, fail if .env or real_configs tracked | P1 | Ready |
| `FIELD_PATHS.md` | All schema field paths, public baseline-building API, AGENTS.md §5 comparison | P1 | Ready |

## `agents/`

| File | What it is | Owner | Status |
|---|---|---|---|
| `agents/backend-agent.md` | Role instructions for the AI working on `core/`, rules, templates | P1 | Ready |
| `agents/frontend-agent.md` | Role instructions for the AI working on `app/` | P1 | Ready |

## `core/` (backend)

| File | What it is | Owner | Status |
|---|---|---|---|
| `core/contracts.py` | Shared data types between frontend and backend. The sync point | P1 | Ready |
| `core/service.py` | The only module the frontend calls. Stubs now, filled in as pieces land | P1 | Ready (stubs) |
| `core/schema.py` | The vendor-neutral Security Baseline Model (pydantic) | P1 | To build |
| `core/compliance.py` | Loads YAML rules and returns Pass / Fail / Unknown per control | P1 | To build |
| `core/ingest.py` | Reads uploaded files, guesses vendor and OS, splits into blocks | P2 | To build |
| `core/redact.py` | Strips passwords, keys, and SNMP strings before any model call | P2 | To build |
| `core/normalize.py` | Mapping lookup, then LLM extraction, then review queue | P2 | To build |
| `core/mappings.py` | SQLite store of admin-approved mappings, seeded from `data/seed_mappings.json` | P2 | To build |
| `core/llm/client.py` | The only code that calls a model. Mock by default, real model via `.env` | P2 | Ready |
| `core/llm/prompts/` | Prompt templates as versioned text files, e.g. `extract_v1.txt` | P2 | To build |
| `core/remediation.py` | Picks fix commands: vendor templates first, LLM for gaps | P3 | To build |
| `core/report.py` | Builds the per-device PDF with ReportLab | P5 | To build |
| `core/__init__.py`, `core/llm/__init__.py` | Empty package markers | P1 | Ready |

## `rules/`, `templates/`, `samples/`

| File | What it is | Owner | Status |
|---|---|---|---|
| `rules/cis.yaml` | About 10 checks to start. Data, not code | P3 | To build |
| `rules/nist.yaml`, `stig.yaml`, `iso.yaml` | Further frameworks, added later | P3 | Later |
| `templates/remediation/<vendor>.yaml` | Fix commands per vendor, keyed by the rule's `remediation` id | P3 | To build |
| `samples/cisco_ios.cfg`, `juniper.conf`, `mikrotik.rsc` | Sanitized sample configs. MikroTik is the "unseen vendor" for the demo | P3 | To build |

## `app/` (frontend)

| File | What it is | Owner | Status |
|---|---|---|---|
| `app/main.py` | Streamlit entry point. Adds the repo root to `sys.path` so `core` imports work | P4 | To build |
| `app/api.py` | Switches between `core.service` and `mock_service` using `USE_MOCK_SERVICE` | P4 | To build |
| `app/mock_service.py` | Fake data with the same signatures as `core/service.py`, so the UI works alone | P4 | To build |
| `app/pages/` | Upload, Dashboard, Device detail, Training pages | P4 | To build |
| `app/__init__.py` | Empty package marker | P4 | Ready |

## `data/`, `scripts/`, `tests/`, `docs/`

| File | What it is | Owner | Status |
|---|---|---|---|
| `data/seed_mappings.json` | Shared starting mappings so every device begins in the same state | P2 | To build |
| `data/*.db` | Per-device learned mappings. Gitignored | auto | Local only |
| `scripts/reset_demo.py` | Resets your local state so the "teach a new vendor" demo can be repeated | P2 | To build |
| `tests/test_<module>.py` | Unit tests, one file per module, written by that module's owner | each owner | To build |
| `tests/golden/` | Expected normalized JSON for each sample config | P3 | To build |
| `tests/test_e2e.py` | Upload samples, audit, check findings and the PDF | P5 | To build |
| `docs/architecture.md` | The 2-page architecture document (a graded deliverable) | P5 | To build |
| `docs/` (slides, video) | 5-slide deck and 2-minute demo video | P5 | To build |

## Quick answers

- **Where do I plug in Gemma 4?** Your own `.env` (see `.env.example` and `TEAM.md` section 4). No code change.
- **What do I call from the UI?** Only `core/service.py`, through `app/api.py`.
- **I need a new field in the data.** Ask P1 to change `core/contracts.py`.
- **Who do I ask about a failing rule?** P3. A wrong extraction? P2. A wrong score? P1. A UI bug? P4. A broken PDF? P5.
