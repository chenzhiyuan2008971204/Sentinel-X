Execute SENTINEL X Phase 3: Multi-Engine Detection.

Implement independent detection adapters:
- ClamAV
- Standalone YARA
- SHA-256 reputation
- PE static analysis

YARA:
- Load local rule collections.
- Validate rules.
- Record matching rule identifiers.
- Handle unsupported modules.
- Support rule versioning.

Hash Intelligence:
- Calculate SHA-256.
- Compare against locally maintained trusted intelligence.
- Distinguish unknown hashes from malicious hashes.

PE Analysis:
- Identify PE files.
- Extract metadata.
- Inspect sections and imports.
- Check digital signature information.
- Report anomalies without automatically declaring malware.

Create a standardized DetectionResult model.
Each engine must be independently testable.
Do not execute analyzed files.
Run integration tests.
