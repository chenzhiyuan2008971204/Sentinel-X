"""Standard engine interface.

Engines receive files in batches because some engines (clamscan) pay a large fixed start-up
cost per invocation. An engine must return exactly one outcome per submitted target; the
orchestrator treats a missing outcome as an engine error, never as "no findings".
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from sentinelx.core.cancel import CancelToken
from sentinelx.core.models import DetectionResult, EngineStatus, ScanTarget


@runtime_checkable
class DetectionEngine(Protocol):
    name: str

    def availability(self, refresh: bool = False) -> EngineStatus:
        """Cached status; `refresh=True` re-probes (e.g. after the user installs the engine)."""
        ...

    def scan_batch(
        self, targets: Sequence[ScanTarget], cancel: CancelToken
    ) -> dict[ScanTarget, DetectionResult]: ...
