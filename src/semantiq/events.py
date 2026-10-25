"""Event models and dispatcher for scan progress."""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Scan lifecycle and progress event types."""
    SCAN_STARTED = "scan_started"
    INSPECTION_COMPLETED = "inspection_completed"
    THREAT_MODEL_BUILT = "threat_model_built"
    FILE_ANALYSIS_STARTED = "file_analysis_started"
    FILE_ANALYZED = "file_analyzed"
    FINDING_DISCOVERED = "finding_discovered"
    VALIDATION_STARTED = "validation_started"
    VALIDATION_COMPLETED = "validation_completed"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"


class ScanEvent(BaseModel):
    """Event payload emitted during analysis."""
    event_type: EventType
    scan_id: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)


EventHandler = Callable[[ScanEvent], None]


class EventBus:
    """Thread-safe event dispatcher for progress listeners."""

    def __init__(self) -> None:
        self._handlers: list[EventHandler] = []

    def subscribe(self, handler: EventHandler) -> None:
        """Register a progress event listener."""
        if handler not in self._handlers:
            self._handlers.append(handler)

    def unsubscribe(self, handler: EventHandler) -> None:
        """Unregister a listener."""
        if handler in self._handlers:
            self._handlers.remove(handler)

    def emit(self, event: ScanEvent) -> None:
        """Dispatch event to all subscribed listeners."""
        import contextlib
        for handler in self._handlers:
            with contextlib.suppress(Exception):
                handler(event)
