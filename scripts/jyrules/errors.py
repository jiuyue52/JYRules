from __future__ import annotations

from pathlib import Path


class BuildError(RuntimeError):
    """Base error for expected JYRules build failures."""


class TaskConfigError(BuildError):
    """Raised when a JYRules task definition is invalid."""

    def __init__(
        self,
        message: str,
        *,
        path: Path | None = None,
        field: str | None = None,
    ) -> None:
        self.message = message
        self.path = path
        self.field = field
        super().__init__(self._render())

    def _render(self) -> str:
        context: list[str] = []
        if self.path is not None:
            context.append(str(self.path))
        if self.field is not None:
            context.append(self.field)
        return f"{': '.join(context)}: {self.message}" if context else self.message


ConfigError = TaskConfigError
