Execute SENTINEL X Phase 6: Windows Behavior Monitoring.

Implement passive security telemetry collection.

Integrate:
- Sysmon events
- Windows Event Log
- psutil
- Selected-directory file monitoring

Features:
- Process creation event ingestion.
- File modification event ingestion.
- Network connection metadata.
- Event timeline.
- Event correlation.
- Alert generation.
- Event filtering.

Requirements:
- Passive monitoring by default.
- No automatic process termination.
- No kernel driver development.
- No disabling Windows security.
- Respect Windows permissions.
- Clearly distinguish observed facts from analytical conclusions.

Use harmless synthetic activity to test the event pipeline.
