"""OpenAI target adapter."""
from __future__ import annotations

from typing import TYPE_CHECKING

from argus.targets.base import Target

if TYPE_CHECKING:
    from openai.types.chat import ChatCompletionMessageParam


class OpenAITarget(Target):
    def __init__(self, model: str = "gpt-4o", api_key: str | None = None,
                 system_prompt: str = "") -> None:
        import openai
        self._client = openai.OpenAI(api_key=api_key)
        self._model = model
        self._system_prompt = system_prompt

    @property
    def name(self) -> str:
        return f"openai/{self._model}"

    def send(self, prompt: str) -> str:
        messages: list[ChatCompletionMessageParam] = []
        if self._system_prompt:
            messages.append({"role": "system", "content": self._system_prompt})
        messages.append({"role": "user", "content": prompt})
        resp = self._client.chat.completions.create(model=self._model, messages=messages)
        return resp.choices[0].message.content or ""
