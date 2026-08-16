"""Anthropic target adapter."""
from __future__ import annotations

from typing import Any

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
        kwargs: dict[str, Any] = {"model": self._model, "max_tokens": 1024,
                        "messages": [{"role": "user", "content": prompt}]}
        if self._system_prompt:
            kwargs["system"] = self._system_prompt
        resp = self._client.messages.create(**kwargs)
        block = resp.content[0]
        if not isinstance(block, anthropic.types.TextBlock):
            raise ValueError(f"Target returned a non-text content block: {type(block).__name__}")
        return block.text
