"""Base fetcher contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FetchResult:
    url: str
    status: int
    html: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    elapsed: float = 0.0
    via_browser: bool = False
    spa_state: dict[str, Any] | None = None
    captured_requests: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class BaseFetcher(ABC):
    @abstractmethod
    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        proxy: str | None = None,
        timeout: float = 30.0,
        **kwargs: Any,
    ) -> FetchResult: ...

    async def close(self) -> None:
        pass

    async def __aenter__(self) -> "BaseFetcher":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
