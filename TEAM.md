# TEAM.md: Five People, Five Devices

How we build NetComply AI without stepping on each other. Read this once, then use it as the reference. Replace P1..P5 with names in the table below and in `.github/CODEOWNERS`.

## 1. Who owns what

| Person | Role | Owns (edit only these) | AI agent file |
|---|---|---|---|
| **P1** | Lead and integrator | `core/contracts.py`, `core/service.py`, `core/schema.py`, `core/compliance.py`, `requirements.txt`, `.github/`, merges to `main` | `agents/backend-agent.md` |
| **P2** | Normalization and LLM | `core/ingest.py`, `core/redact.py`, `core/normalize.py`, `core/mappings.py`, `core/llm/`, `data/seed_mappings.json`, `scripts/` | `agents/backend-agent.md` |
| **P3** | Rules and content | `rules/`, `templates/remediation/`, `samples/`, `core/remediation.py`, `tests/golden/` | `agents/backend-agent.md` |
| **P4** | Frontend | `app/` (including `app/mock_service.py`) | `agents/frontend-agent.md` |
| **P5** | Reports, QA, deliverables | `core/report.py`, `tests/test_e2e.py`, `README.md`, `docs/`, slides, demo video | `agents/backend-agent.md` for `report.py` only |

Each person also owns the unit tests for their own modules (`tests/test_<module>.py`).

## 2. The rules that make multi-device work

1. **Edit only files you own.** If you need a change in someone else's file, message them. Separate files mean almost no merge conflicts.
2. **The contract is the sync point.** `core/contracts.py` and `core/service.py` define what the frontend and backend exchange. They are already in the repo. Changing them needs a PR labeled `contract`, approved by P1, and a heads-up to P4.
3. **Mock first.** Nobody waits for anybody. P4 builds against `app/mock_service.py` (`USE_MOCK_SERVICE=1`). Everyone else runs the LLM in `mock` mode (default). Tests always use the mock.
4. **Each device has its own `.env`.** It is never committed. Copy `.env.example` and edit your copy.
5. **Per-device state is not shared.** The learned-mappings database (`data/*.db`) is gitignored, so each laptop has its own. Shared demo state lives in `data/seed_mappings.json`, which `mappings.py` loads into an empty database. Reset your state with `python scripts/reset_demo.py` (P2 writes this).
6. **Only sanitized sample configs go in git.** Never commit real device configs, keys, or passwords.
7. **Dependencies:** ask P1, or add a line under your own heading in `requirements.txt`.

## 3. Setting up your device (about 10 minutes)

Requires Python 3.11+ and Git.

**macOS / Linux**
```bash
git clone <repo-url> && cd <repo>
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
pytest -q
```

**Windows (PowerShell)**
```powershell
git clone <repo-url>; cd <repo>
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
pytest -q
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass` first.

Run the app from the repo root: `streamlit run app/main.py`. For P4's first version, set `USE_MOCK_SERVICE=1` in your `.env`.

**Check:** `pytest -q` runs without import errors, and `python -c "import core.contracts"` prints nothing.

## 4. Choosing how your device talks to the model

Set this in your own `.env`. The code is identical in every mode.

| Mode | `.env` | Use when |
|---|---|---|
| **A. Mock (default)** | `LLM_BACKEND=mock` | Always works, no key. Everyone starts here. Tests use this. |
| **B. Local model** | `LLM_BACKEND=openai_compat`, `LLM_BASE_URL=http://localhost:11434/v1`, `LLM_MODEL=<id>` | Your laptop has the RAM or GPU to run it (Ollama is one example; any OpenAI-compatible server works) |
| **C. Shared on LAN** | `LLM_BASE_URL=http://<host-ip>:11434/v1`, `LLM_MODEL=<id>`, `LLM_ALLOWED_HOSTS=<host-ip>` | One teammate's machine runs the model for others |
| **D. Hosted API (dev only)** | `OFFLINE=0`, `LLM_BASE_URL=<provider url>`, `LLM_API_KEY=<key>`, `LLM_MODEL=<id>` | You have an API key. Never commit it. |

Notes:
- For mode C, the host must expose the server on the network (for Ollama, start it with `OLLAMA_HOST=0.0.0.0`). Venue wifi often blocks device-to-device traffic. If so, use a phone hotspot.
- Modes C and D send text to another machine. Use sample configs only.
- Before the demo, switch to A, B, or C with `OFFLINE=1`, so the "your configs never leave your network" claim is true.
- Check Gemma 4's actual availability and model ID with your provider or runtime. Do not guess it.

## 5. Git workflow

```bash
git checkout -b p2/normalize          # branch name: <you>/<topic>
# ...work, commit small and often...
git pull --rebase origin main         # every ~30 min
git push origin p2/normalize
```

- Open a PR into `main`. P1 merges (or anyone, after the checks below).
- Before pushing: `pytest -q` and `ruff check .` must pass.
- Commit messages: `area: what changed`, e.g. `redact: strip snmp communities`.
- If a rebase conflicts, you touched a file you do not own. Stop and ask the owner.
- Never force-push to `main`.

## 6. Plan (shares of total time)

| Phase | Time | P1 | P2 | P3 | P4 | P5 |
|---|---|---|---|---|---|---|
| **0. Setup** | ~10% | Create repo, add everyone | Setup, mock check | Setup | Setup | Setup |
| **1. Foundations** | ~15% | `schema.py`, `service.py` wiring | `redact.py`, `ingest.py` | Cisco sample, 10 rules (field names are in `AGENTS.md` section 5) | `api.py`, `mock_service.py`, Upload page | Report layout using fake `DeviceResult`, doc skeletons |
| **2. Vertical slice** | ~35% | `compliance.py` | `normalize.py` + mock LLM | Remediation templates, golden JSON | Dashboard, Device page | `report.py` real data |
| **3. Integrate** | ~20% | Wire `service.py`, switch `USE_MOCK_SERVICE=0` | `mappings.py`, training flow | Juniper and MikroTik samples | Training page, re-audit | `test_e2e.py` |
| **4. Finish** | ~20% | Connect real model, fix bugs | Prompt tuning, reset script | Fix rules and templates | Polish, LLM badge | README, architecture doc, slides, video |

**Sync point** at the end of each phase (5 minutes): what is done, what blocks you, what changes in the contract.

## 7. Telling your AI coding tool who you are

Start each session with:

> Read `AGENTS.md`, `agents/<your role>.md`, and `TEAM.md`. I am **P2**. Edit only the files P2 owns in `TEAM.md`. If I need a change elsewhere, tell me who to ask.

## 8. Pre-demo checklist

- [ ] `main` is merged and everyone has pulled
- [ ] `USE_MOCK_SERVICE=0` and the app runs end to end on the demo laptop
- [ ] Demo laptop `.env` has `OFFLINE=1` and a local or LAN model (or mock, stated honestly)
- [ ] The "unseen vendor" flow works after `python scripts/reset_demo.py`
- [ ] PDF downloads and opens
- [ ] `pytest -q` passes
- [ ] No `.env`, keys, or real configs in the repo
- [ ] README, architecture doc (2 pages), slides (5), video (2 min) are done
- [ ] A backup demo video exists in case wifi or the model fails

## 9. Quick commands

No `make` file is used. Run these from the repo root:

```bash
# Run the full test suite (mock LLM backend, offline)
pytest -q

# Lint
ruff check .

# Format
ruff format .

# Run the Streamlit app
streamlit run app/main.py
```
