"""Check registry — auto-imports built-in checks and exposes a name lookup."""

from __future__ import annotations

from asms_worker.checks.base import Check
from asms_worker.checks.headers import SecurityHeadersCheck


class _Registry:
    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def register(self, check: Check) -> None:
        if check.name in self._checks:
            raise ValueError(f"Check {check.name!r} already registered")
        self._checks[check.name] = check

    def get(self, name: str) -> Check:
        try:
            return self._checks[name]
        except KeyError as exc:
            raise KeyError(f"Unknown check {name!r}. Known: {sorted(self._checks)}") from exc

    def names(self) -> list[str]:
        return sorted(self._checks)


REGISTRY = _Registry()
REGISTRY.register(SecurityHeadersCheck())
