"""Ready-made observers for ``WAPServer(observer=...)``.

A WAP server reports what happens to each request as ``observer(event, attributes)``:

========================== ==========================================================
``request.completed``      ``capability``, ``tier``, ``duration_ms``
``request.failed``         ``code``, ``capability``, ``tier`` (the action raised)
``request.rejected``       ``code`` (``rate_limited``, ``pow_invalid``, ``loop_detected``,
                           ``forbidden``, ...), plus ``scope``/``tier``/``reason`` when known
``request.idempotent_replay`` ``capability``
``pow.issued``             ``difficulty``
========================== ==========================================================

Use :class:`LoggingObserver` for structured logs, :class:`MetricsObserver` for
in-process counters and latency percentiles (e.g. to export to Prometheus or
OpenTelemetry), or :func:`combine` to send events to several observers. Any
callable with the same signature works; observer errors are logged and never
affect requests.
"""

from __future__ import annotations

import json
import logging
import math
import threading
from collections import Counter, defaultdict, deque
from collections.abc import Callable
from typing import Any

Observer = Callable[[str, dict[str, Any]], None]


class LoggingObserver:
    """Emit one structured log line (JSON attributes) per event."""

    def __init__(self, logger: logging.Logger | None = None, level: int = logging.INFO) -> None:
        self.logger = logger or logging.getLogger("wap.events")
        self.level = level

    def __call__(self, event: str, attributes: dict[str, Any]) -> None:
        level = logging.WARNING if event == "request.rejected" else self.level
        self.logger.log(level, "%s %s", event, json.dumps(attributes, default=str, sort_keys=True))


class MetricsObserver:
    """Thread-safe counters by (event, code/tier/capability) plus latency percentiles per capability."""

    def __init__(self, max_samples: int = 10_000) -> None:
        self._lock = threading.Lock()
        self.counters: Counter[tuple[str, str]] = Counter()
        self._latency: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=max_samples))

    def __call__(self, event: str, attributes: dict[str, Any]) -> None:
        label = str(attributes.get("code") or attributes.get("capability") or attributes.get("difficulty") or "")
        with self._lock:
            self.counters[(event, label)] += 1
            if event == "request.completed" and "duration_ms" in attributes:
                self._latency[str(attributes.get("capability"))].append(float(attributes["duration_ms"]))

    def count(self, event: str, label: str | None = None) -> int:
        with self._lock:
            if label is not None:
                return self.counters[(event, label)]
            return sum(v for (e, _), v in self.counters.items() if e == event)

    def percentile(self, capability: str, q: float) -> float | None:
        with self._lock:
            samples = sorted(self._latency.get(capability, ()))
        if not samples:
            return None
        # Nearest-rank method.
        rank = max(1, math.ceil(q / 100 * len(samples)))
        return samples[min(rank, len(samples)) - 1]

    def snapshot(self) -> dict[str, Any]:
        """A JSON-friendly view, e.g. for a ``/metrics`` endpoint of your own."""
        with self._lock:
            counters = {f"{event}{{{label}}}" if label else event: n for (event, label), n in self.counters.items()}
            capabilities = list(self._latency)
        return {
            "counters": counters,
            "latency_ms": {
                cap: {q: self.percentile(cap, float(q[1:])) for q in ("p50", "p95", "p99")} for cap in capabilities
            },
        }


def combine(*observers: Observer) -> Observer:
    """Fan one event out to several observers."""

    def observe(event: str, attributes: dict[str, Any]) -> None:
        for observer in observers:
            try:
                observer(event, attributes)
            except Exception:  # noqa: BLE001 - one failing sink must not starve the others
                logging.getLogger("wap.server").exception("observer %r failed for %r", observer, event)

    return observe


__all__ = ["LoggingObserver", "MetricsObserver", "Observer", "combine"]
