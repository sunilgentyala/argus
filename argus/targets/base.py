"""Target interface."""
from abc import ABC, abstractmethod


class Target(ABC):
    @abstractmethod
    def send(self, prompt: str) -> str: ...
    @property
    @abstractmethod
    def name(self) -> str: ...
