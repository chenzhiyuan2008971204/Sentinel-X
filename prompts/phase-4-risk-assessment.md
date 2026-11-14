Execute SENTINEL X Phase 4: Risk Assessment Engine.

Build an evidence-based threat classification system.

Classifications:
- CLEAN
- UNKNOWN
- SUSPICIOUS
- CONFIRMED_THREAT

Implement:
- Detection evidence aggregation.
- Independent engine result comparison.
- Evidence reliability assessment.
- False positive management.
- Risk explanation.
- Confidence reporting.
- Manual review workflow.

Important:
- A single weak heuristic must not confirm malware.
- Missing signatures must not imply malicious behavior.
- Do not interpret a numeric risk score as malware probability.
- Preserve individual engine results.
- Explain why every classification was assigned.

Create extensive tests for conflicting detection results.
