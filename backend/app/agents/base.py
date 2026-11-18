"""Base agent protocol and abstract class."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from pydantic import BaseModel

InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


class BaseAgent(ABC, Generic[InputT, OutputT]):
    """
    Abstract base class for all SOC agents.

    Each agent has:
    - A name for logging and audit
    - Typed input/output schemas
    - A run method that processes input and returns output
    - Built-in timing for performance tracking
    """

    name: str = "base_agent"

    @abstractmethod
    async def run(self, input_data: InputT) -> OutputT:
        """Process input and return structured output."""
        ...

    async def execute(self, input_data: InputT) -> tuple[OutputT, int]:
        """
        Run the agent and return (output, duration_ms).
        Wraps run() with timing.
        """
        start = time.perf_counter()
        result = await self.run(input_data)
        duration_ms = int((time.perf_counter() - start) * 1000)
        return result, duration_ms
