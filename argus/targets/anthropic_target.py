"""Anthropic target adapter."""
from __future__ import annotations
import anthropic
from argus.targets.base import Target

class AnthropicTarget(Target):
    def __init__(self, model: str = "claude-sonnet-4-6",
                 api_key: str | None = None, system_prompt: str = "") -> None:
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._system_prompt = system_prompt

    @property
    def name(self) -> str:
        return f"anthropic/{self._model}"

    def send(self, prompt: str) -> str:
        kwargs: dict = {"model": self._model, "max_tokens": 1024,
                        "messages": [{"role": "user", "content": prompt}]}
        if self._system_prompt:
            kwargs["system"] = self._system_prompt
        resp = self._client.messages.create(**kwargs)
        return resp.content[0].text
