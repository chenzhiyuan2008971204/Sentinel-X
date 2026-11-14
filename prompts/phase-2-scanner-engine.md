Execute SENTINEL X Phase 2: Scanner Engine.

Implement:
- Single file scanning.
- Directory scanning.
- Recursive scanning.
- File metadata collection.
- SHA-256 calculation.
- Scan progress tracking.
- Scan cancellation.
- Permission error handling.
- Scan history persistence.
- Exclusion management.

Integrate ClamAV through a properly isolated adapter.

Requirements:
- Do not assume ClamAV is installed.
- Verify engine availability.
- Display engine version.
- Distinguish engine errors from clean results.
- Never report a scan as successful when the engine failed.
- Protect against symlink traversal.
- Apply file size and resource limits.
- Support asynchronous GUI operations.

Test using EICAR and harmless files.
Run all tests before completion.
