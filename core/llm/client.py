"""Single entry point for ALL model calls.

Switching from the mock to Gemma 4 is a .env change only:
    LLM_BACKEND=openai_compat
    LLM_BASE_URL=<your endpoint>
    LLM_MODEL=<gemma 4 model id>
    LLM_API_KEY=<key, if the endpoint needs one>

Callers must pass text that is ALREADY REDACTED (see core/redact.py).
No other module may import a model SDK or call a model endpoint.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

try:  # load .env from the repo root if python-dotenv is installed
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class LLMError(Exception):
    """Raised for config problems, network failures, or unparseable output."""


@dataclass(frozen=True)
class LLMConfig:
    backend: str
    base_url: str
    model: str
    api_key: str
    offline: bool
    timeout_s: float
    allowed_hosts: tuple[str, ...] = ()  # extra hosts permitted when OFFLINE=1 (e.g. a teammate's LAN IP)


def load_config() -> LLMConfig:
    return LLMConfig(
        backend=os.getenv("LLM_BACKEND", "mock").strip().lower(),
        base_url=os.getenv("LLM_BASE_URL", "http://localhost:11434/v1").rstrip("/"),
        model=os.getenv("LLM_MODEL", "").strip(),
        api_key=os.getenv("LLM_API_KEY", "").strip(),
        offline=os.getenv("OFFLINE", "1") == "1",
        timeout_s=float(os.getenv("LLM_TIMEOUT_S", "60")),
        allowed_hosts=tuple(
            h.strip() for h in os.getenv("LLM_ALLOWED_HOSTS", "").split(",") if h.strip()
        ),
    )


class LLMClient:
    def __init__(self, cfg: LLMConfig | None = None) -> None:
        self.cfg = cfg or load_config()
        self._validate()

    # ---- public API -------------------------------------------------
    def status(self) -> dict:
        """Used by the UI badge so users can see which backend is active."""
        c = self.cfg
        return {
            "backend": c.backend,
            "model": c.model or "(none)",
            "offline_mode": c.offline,
            "ready": c.backend == "mock" or bool(c.model),
        }

    def complete_json(self, system: str, user: str) -> dict:
        """Return a parsed JSON object. Retries once on unparseable output."""
        last_err: Exception | None = None
        for _ in range(2):
            raw = self._call(system, user)
            try:
                return _parse_json(raw)
            except LLMError as e:
                last_err = e
        raise LLMError(f"Model returned invalid JSON twice: {last_err}")

    # ---- internals --------------------------------------------------
    def _validate(self) -> None:
        c = self.cfg
        if c.backend == "mock":
            return
        if c.backend != "openai_compat":
            raise LLMError(f"Unknown LLM_BACKEND '{c.backend}' (use 'mock' or 'openai_compat')")
        if not c.model:
            raise LLMError("LLM_MODEL is not set")
        host = urlparse(c.base_url).hostname
        if c.offline and host not in LOCAL_HOSTS and host not in c.allowed_hosts:
            raise LLMError(
                f"OFFLINE=1 but LLM_BASE_URL points to '{host}'. "
                "Use a local endpoint, add the host to LLM_ALLOWED_HOSTS, or set OFFLINE=0 for development."
            )

    def _call(self, system: str, user: str) -> str:
        if self.cfg.backend == "mock":
            return json.dumps(_mock_extract(user))
        headers = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        body = {
            "model": self.cfg.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            r = requests.post(
                f"{self.cfg.base_url}/chat/completions",
                headers=headers,
                json=body,
                timeout=self.cfg.timeout_s,
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (requests.RequestException, KeyError, IndexError, ValueError) as e:
            raise LLMError(f"Model call failed: {e}") from e


def _parse_json(raw: str) -> dict:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)  # strip code fences
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise LLMError(f"Not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise LLMError("Expected a JSON object")
    return obj


# ---- mock backend: lets the whole app run with no model or key ----------
_MOCK_RULES = [
    (r"^\s*ip ssh version (\d)", "management.ssh_version", lambda m: int(m.group(1))),
    (r"transport input .*telnet", "management.telnet_enabled", lambda m: True),
    (r"^\s*ip http server", "management.http_server_enabled", lambda m: True),
    (r"^\s*logging host (\S+)", "logging.syslog_servers", lambda m: [m.group(1)]),
    (r"^\s*service password-encryption", "authentication.password_encryption", lambda m: True),
]


def _mock_extract(user_text: str) -> dict:
    """Deterministic stand-in for the model. DEMO ONLY: not a real parser."""
    out = []
    for line in user_text.splitlines():
        for pattern, field, to_value in _MOCK_RULES:
            m = re.search(pattern, line)
            if m:
                out.append({"field": field, "value": to_value(m),
                            "source_line": line.strip(), "confidence": 0.95})
    return {"extractions": out}
