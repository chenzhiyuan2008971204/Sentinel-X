Execute SENTINEL X Phase 5: Quarantine Manager.

Implement a secure quarantine subsystem.

Features:
- Quarantine confirmed threats after user confirmation.
- Store original path and SHA-256.
- Preserve file integrity metadata.
- Restrict access to quarantined content.
- Prevent accidental execution.
- Verify integrity before restoration.
- Record all operations.
- Support restoration with explicit confirmation.
- Detect duplicate quarantine entries.

Security:
- Use safe file handling.
- Prevent path traversal.
- Avoid race conditions.
- Never automatically permanently delete files.
- Do not follow unsafe symbolic links.
- Protect against unauthorized restoration.

Test with harmless synthetic files.
