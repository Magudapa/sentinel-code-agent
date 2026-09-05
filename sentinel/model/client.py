"""Zero-dependency model client: local Ollama by default, OpenAI-compatible fallback.

No `litellm`/`openai` dependencies — just `requests`. This keeps Sentinel installable
and 100% free out of the box.
"""

from __future__ import annotations

import re

import requests

from ..config import ModelConfig


class ModelUnavailableError(RuntimeError):
    pass


class ModelClient:
    def __init__(self, config: ModelConfig | None = None):
        self.config = config or ModelConfig()

    # ---- raw chat ----------------------------------------------------
    def chat(self, system: str, user: str) -> str:
        if self.config.provider == "openai":
            return self._chat_openai(system, user)
        return self._chat_ollama(system, user)

    def _chat_ollama(self, system: str, user: str) -> str:
        url = self.config.base_url.rstrip("/") + "/api/chat"
        payload = {
            "model": self.config.model,
            "stream": False,
            "options": {"temperature": self.config.temperature, "num_predict": self.config.max_tokens, "num_ctx": 2048},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            r = requests.post(url, json=payload, timeout=600)
        except requests.RequestException as e:
            raise ModelUnavailableError(
                f"Cannot reach Ollama at {self.config.base_url}. Is `ollama serve` running?"
                f" ({e})"
            )
        if r.status_code != 200:
            raise ModelUnavailableError(f"Ollama returned HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        return data.get("message", {}).get("content", "").strip()

    def _chat_openai(self, system: str, user: str) -> str:
        from ..config import DEFAULT_MODEL

        url = self.config.base_url.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        payload = {
            "model": self.config.model or DEFAULT_MODEL,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=120)
        except requests.RequestException as e:
            raise ModelUnavailableError(f"Cannot reach model API at {self.config.base_url}: {e}")
        if r.status_code != 200:
            raise ModelUnavailableError(f"Model API returned HTTP {r.status_code}: {r.text[:200]}")
        return r.json()["choices"][0]["message"]["content"].strip()

    # ---- review helpers ----------------------------------------------
    def is_available(self) -> bool:
        """Fast availability probe - checks the model registry, does not load the model."""
        if self.config.provider != "ollama":
            try:
                return bool(self.chat("Reply with the single word: ok", "ping"))
            except ModelUnavailableError:
                return False
        try:
            r = requests.get(self.config.base_url.rstrip("/") + "/api/tags", timeout=5)
            if r.status_code != 200:
                return False
            names = [m.get("name", "") for m in r.json().get("models", [])]
            if not names:
                return False
            # Accept any model unless a specific one is configured
            return any(self.config.model.split(":")[0] in n or n in self.config.model for n in names) or len(names) > 0
        except requests.RequestException:
            return False

    def explain_finding(self, finding, language: str = "") -> dict:
        """Ask the model to explain a finding and suggest a concrete patch.

        Returns {"explanation": str, "suggested_fix": str or ""}
        """
        system = (
            "You are Sentinel, an expert senior security code-reviewer. Your job is to "
            "explain ONE finding concisely (max 4 sentences) and propose a concrete minimal "
            "code fix when one clearly exists. Follow the exact JSON output format. "
            "Never invent issues. If no clear fix exists, set suggested_fix to an empty string."
        )
        snippet = finding.code_snippet or ""
        user = (
            "REVIEW FINDING\n"
            f"- Rule: {finding.rule_id}\n"
            f"- Severity: {finding.severity_name}\n"
            f"- Description: {finding.description}\n"
            f"- File: {finding.file}:{finding.line}\n"
            f"- Helper advice: {finding.suggested_fix}\n"
            f"- Detected code:\n```{language}\n{snippet}\n```\n\n"
            'Return JSON with exactly two keys: "explanation" (string) and '
            '"suggested_fix" (string containing only the corrected code snippet, or "").'
        )
        raw = self.chat(system, user)
        return self._parse_structured(raw, snippet)

    def _parse_structured(self, raw: str, fallback_snippet: str) -> dict:
        explanation = raw
        fix = ""
        try:
            import json as _json

            m = re.search(r"\{[\s\S]*\}", raw)
            if m:
                data = _json.loads(m.group(0))
                explanation = data.get("explanation", raw)
                fix = data.get("suggested_fix", "")
        except Exception:
            pass
        return {"explanation": explanation, "suggested_fix": fix or fallback_snippet}


def extract_llm_fix(raw: str) -> str:
    """Extract a code block from an LLM patch response."""
    m = re.search(r"```(?:\w+)?\s*\n([\s\S]*?)```", raw)
    if m:
        return m.group(1).strip()
    return raw.strip()