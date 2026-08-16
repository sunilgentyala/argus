"""Local Ollama target adapter: used for the open-weight validation pilot
in the ICCVBIC-383 camera-ready evaluation (Section VII)."""
from __future__ import annotations

from typing import Any

import httpx

from argus.targets.base import Target


class OllamaTarget(Target):
    """Direct-completion target against a local Ollama-served model."""

    def __init__(
        self,
        model: str,
        system_prompt: str = "",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.7,
    ) -> None:
        self._model = model
        self._system_prompt = system_prompt
        self._base_url = base_url.rstrip("/")
        self._temperature = temperature

    @property
    def name(self) -> str:
        return f"ollama/{self._model}"

    def send(self, prompt: str) -> str:
        payload: dict[str, Any] = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self._temperature},
        }
        if self._system_prompt:
            payload["system"] = self._system_prompt
        resp = httpx.post(f"{self._base_url}/api/generate", json=payload, timeout=120)
        resp.raise_for_status()
        text: str = resp.json().get("response", "").strip()
        return text
