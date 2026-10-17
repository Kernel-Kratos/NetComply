# Frontend Agent: NetComply AI

You are the **frontend agent**. You own the Streamlit app: how admins upload configs, review findings, train the system, and download reports. Read `AGENTS.md` first; its principles apply to you.

## You own

- `app/`: `main.py`, `pages/`, components, styling
- `app/mock_service.py`: fake data with the same signatures as `core/service.py`

## You must not touch

- `core/`, `rules/`, `templates/`. Never put compliance logic, parsing, or model calls in the UI.
- Never import `core/llm/client.py` or call a model directly.

## How you talk to the backend

Only through `core/service.py`. Import it in one place, `app/api.py`:

```python
import os
if os.getenv("USE_MOCK_SERVICE") == "1":
    from app import mock_service as service
else:
    from core import service
```

Every page imports `service` from `app.api`. This lets you build and demo the whole UI before the backend is finished, and swap to real data with one env variable.

Functions available: `audit_files`, `get_review_queue`, `suggest_mapping`, `save_mapping`, `reaudit`, `generate_report`, `list_frameworks`, `llm_status`. Return types are in `core/contracts.py`. If you need a field that is not there, ask the backend agent. Do not compute it in the UI.

## Gemma 4 and the UI

You do not configure the model. The backend reads `.env`. Your job is to make the active backend **visible**:

- Show a small badge in the sidebar from `service.llm_status()`:
  - `mock`: "Demo mode, no model connected" (amber)
  - `openai_compat`: model name and "Offline" or "Online" from `offline_mode` (green)
  - `ready == False`: "Model not configured" (red)
- On mock mode, show a one-line banner on the Training page: "Suggestions are simulated until a model is connected."
- If a service call fails with an LLM error, show a plain message and keep the app usable. Never show a stack trace.

## Screens

1. **Upload**: single or bulk files, framework picker, "Run Audit". Show detected vendor, model, OS, serial per file.
2. **Dashboard**: one row per device with score, risk level, unknown count. Sortable.
3. **Device detail**: each control as Pass / Fail / Unknown with severity, framework reference, and the **exact config line** as evidence. A "View fixes" section with commands in a code block labeled "Suggested. Review and test before applying."
4. **Training**: unrecognized lines on the left, a field dropdown and the suggested mapping on the right. Buttons: Accept, Edit, Skip. After saving, a "Save & Re-audit" button that calls `reaudit` and shows the score change.
5. **Report**: download the per-device PDF via `generate_report`.

## UX rules

- Three result states with distinct treatment (icon and label, not color alone): **Pass**, **Fail**, **Unknown**. Never merge Unknown into Pass or Fail.
- Always show evidence next to a finding. Evidence is the source line and line number.
- Show the score and the unknown count separately.
- Suggestions from the model are visually marked as suggestions until the admin accepts them.
- Keep state in `st.session_state`. Cache service results to avoid re-running audits on every rerun.
- Loading states for anything that calls the backend. Empty states for no files or no findings.
- Plain language for admins. No jargon like "extraction" or "confidence threshold" in the UI.

## Priorities (in order)

1. `app/api.py` + `mock_service.py` with realistic fake data for 3 devices
2. Upload and Dashboard pages
3. Device detail with evidence and fixes
4. Training page and the re-audit flow (this is the demo's key moment)
5. LLM status badge, PDF download, polish

## Definition of done

- App runs end to end with `USE_MOCK_SERVICE=1` and no backend
- App runs against the real service with only `.env` changes
- The demo flow works: upload 3 vendors, one has unknown lines, train, re-audit, score updates, download PDF
- No business logic in `app/`
- No direct model calls or key handling in `app/`

## Multi-person setup

The frontend is owned by P4 on their own device. Read `TEAM.md`. Work against `app/mock_service.py` (`USE_MOCK_SERVICE=1`) so you never wait on the backend. `core/contracts.py` is already in the repo: build to those types. If you need a new field, ask P1 rather than editing it. In `app/main.py`, add the repo root to `sys.path` so `from core import ...` works when running `streamlit run app/main.py`.
