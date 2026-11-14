# Sentinel X — Database Schema (SQLite via SQLAlchemy 2.x)

Conventions
- Primary keys are integer autoincrement unless noted. Timestamps are UTC ISO-8601 text (`YYYY-MM-DDTHH:MM:SSZ`).
- Pragmas on connect: `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`.
- Schema version is tracked in `schema_meta`; migrations are forward-only scripts (`MIGRATIONS` in `storage/orm.py`). Before migrating, the database is copied to `sentinelx.db.bak-v<old>`.
- Current version: **5** (v2 adds `engine_runs.info_json`; v3 adds `verdicts.confidence`, `verdicts.needs_review`, `verdicts.assessor_version` and the `fp_suppressions` table; v4 adds quarantine metadata columns; v5 adds `security_events.details_json`, `alerts.rule_id`, `alerts.dedup_key`, `alerts.updated_at` and two indexes).
- `security_events.kind`: PROCESS_CREATE, NET_CONNECT, FILE_CREATE, FILE_MODIFY, FILE_DELETE, FILE_MOVE, AV_DETECTION. `alerts.observed_facts` holds facts only; `alerts.analytic_notes` holds the interpretation.
- `engine_runs.outcome = SKIPPED` means "engine not applicable to this file type" (e.g. PE analysis of a text file) and counts as completed.
- `intel_hashes.category` holds `MALICIOUS` or `KNOWN_GOOD`; `intel_sources.trust_level` holds `HIGH`, `MEDIUM` or `LOW`.
- Enumerations are stored as text with CHECK constraints.

## Tables

### schema_meta
| column | type | notes |
|---|---|---|
| key | TEXT PK | e.g. `schema_version` |
| value | TEXT | |

### scan_jobs
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| started_at / finished_at | TEXT | finished_at nullable |
| status | TEXT | `RUNNING, COMPLETED, PARTIAL, CANCELLED, FAILED`. PARTIAL = finished but some non-excluded files were not fully assessed. FAILED includes "no engine available". |
| targets_json | TEXT | list of roots |
| options_json | TEXT | limits, enabled engines, follow_links flag |
| files_seen / files_assessed / files_not_assessed | INTEGER | |
| error_summary | TEXT | nullable |

### files
Unique per content+path observation.
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| sha256 | TEXT | indexed; NULL when the file could not be read (permission error, skipped by limits) |
| size | INTEGER | nullable |
| path | TEXT | as observed (display) |
| path_norm | TEXT | normalized, casefolded; indexed |
| mtime / ctime | TEXT | |
| first_seen_at / last_seen_at | TEXT | |

### file_scans
One assessment of one file within one job.
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| job_id | FK scan_jobs | |
| file_id | FK files | |
| assessed | INTEGER | 0 if not fully assessed (error, permission, too large) |
| not_assessed_reason | TEXT | nullable |
| verdict_id | FK verdicts | nullable until risk step completes |

### engine_runs
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| file_scan_id | FK file_scans | |
| engine_name / engine_version | TEXT | |
| rules_version | TEXT | signature or rule-set version/date |
| outcome | TEXT | `FINDINGS, NO_FINDINGS, ERROR, SKIPPED` |
| error_detail | TEXT | nullable |
| started_at / duration_ms | TEXT / INTEGER | |
| info_json | TEXT | v2. Non-detection facts from the engine (PE metadata, hash reputation UNKNOWN/KNOWN_GOOD, signature status, backend). Default `{}`. |

### detections
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| engine_run_id | FK engine_runs | |
| rule_id | TEXT | signature/rule name |
| severity_hint | TEXT | `INFO, LOW, MEDIUM, HIGH` |
| evidence_json | TEXT | typed evidence payload |
| confidence_explanation | TEXT | |
| detected_at | TEXT | |
| file_sha256 | TEXT | denormalized for integrity of the record |

### verdicts
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| file_id | FK files | |
| classification | TEXT | `CLEAN, UNKNOWN, SUSPICIOUS, CONFIRMED_THREAT` |
| ordinal_score | INTEGER | sorting aid only, not a probability |
| explanation | TEXT | why this class was assigned |
| contributing_detection_ids | TEXT | JSON list |
| created_at | TEXT | |
| superseded_by | FK verdicts | nullable; the latest verdict of a file has NULL |
| confidence | TEXT | v3. 高 / 中 / 低 / 人工確認 / — (qualitative, not a probability) |
| needs_review | INTEGER | v3. 1 = waiting for manual review |
| assessor_version | TEXT | v3. Rule set that produced it, e.g. `risk-rules-1` |

`file_scans.verdict_id` keeps the verdict assigned at scan time; later reviews add newer verdicts for the same file.

### fp_suppressions (v3)
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| sha256 | TEXT | indexed |
| rule_id | TEXT | NULL = every rule for this hash |
| reason | TEXT NOT NULL | |
| created_at | TEXT | |
| active | INTEGER | deactivated, never deleted |
| review_id | FK manual_reviews | review that created it |

### manual_reviews
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| verdict_id | FK verdicts | |
| decision | TEXT | `CONFIRM, DISMISS_FALSE_POSITIVE, ESCALATE` |
| reason | TEXT NOT NULL | |
| reviewed_at | TEXT | |

### exclusions
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| kind | TEXT | `PATH, PATH_PREFIX, EXTENSION, SHA256` |
| value | TEXT | |
| reason / created_at | TEXT | |
| enabled | INTEGER | |

### quarantine_items
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| vault_id | TEXT UNIQUE | uuid, name of the stored object |
| original_path | TEXT | |
| sha256 | TEXT | hash at intake |
| size | INTEGER | |
| verdict_id | FK verdicts | nullable |
| confirmed_by_user_at | TEXT | |
| status | TEXT | `QUARANTINED, RESTORED, RETAINED_ERROR` |
| restored_at | TEXT | nullable |
| zone_identifier | TEXT | nullable, saved MOTW stream |
| xor_key | TEXT | v4. hex, per-item obfuscation key |
| duplicate_of | FK quarantine_items | v4. first item with the same SHA-256 |
| original_mtime / original_attributes | TEXT / INTEGER | v4. integrity metadata |
| reason | TEXT | v4. user-supplied reason |
| restore_target | TEXT | v4. where it was restored |
| audit_entry_id | FK audit_log | v4. the QUARANTINE entry; restore requires it to match |
| error_detail | TEXT | v4. for RETAINED_ERROR |

No hard-delete status exists by design.

### security_events
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| source | TEXT | `SYSMON, EVENTLOG, PSUTIL, FSWATCH` |
| kind | TEXT | `PROCESS_CREATE, FILE_CHANGE, NET_CONNECT, ...` |
| occurred_at | TEXT | |
| process_name / process_path / pid / ppid / command_line | TEXT/INT | command lines are stored as observed and escaped on display |
| target_path | TEXT | nullable |
| remote_addr / remote_port | TEXT / INTEGER | nullable |
| sha256 | TEXT | nullable, when known |
| raw_ref | TEXT | event record id or channel reference |

Indexes: `(occurred_at)`, `(sha256)`, `(process_path)`.

### alerts
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| created_at | TEXT | |
| title | TEXT | |
| observed_facts | TEXT | JSON list |
| analytic_notes | TEXT | hypotheses, clearly separate from facts |
| severity | TEXT | |
| event_ids | TEXT | JSON list |
| status | TEXT | `OPEN, ACKNOWLEDGED, DISMISSED` |

### intel_sources / intel_hashes
- `intel_sources(id, name, version, imported_at, trust_level, origin_note)`
- `intel_hashes(id, source_id FK, sha256, label, category, added_at)`; unique `(source_id, sha256)`. A hash absent from this table means UNKNOWN, never clean.

### rule_sets
`id, kind (YARA), name, version, path, sha256_of_rules, enabled, validated_at, validation_error`

### reports
`id, kind (JSON/HTML/PDF), created_at, subject_type, subject_ref, path, sha256, tool_versions_json`

Used since Phase 7 (no schema change). `subject_type`: `SAMPLE` (ref = SHA-256), `COMPARISON` (ref = `<sha A>:<sha B>`), `SCAN_JOB` (ref = job id). `sha256` is the report file's hash at creation; the Reports page compares it with the file to show "unchanged / modified / missing". Rows are never deleted. Each creation is also an audit entry `REPORT_CREATE` with the same hash.

Audit actions added in Phase 7: `LAB_INSPECT`, `LAB_COMPARE`, `YARA_TEST`, `REPORT_CREATE`, `REPORT_EXPORT`.

### audit_log
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| at | TEXT | |
| actor | TEXT | `USER` or `SYSTEM` |
| action | TEXT | e.g. `QUARANTINE`, `RESTORE`, `EXCLUSION_ADD`, `SCAN_START` |
| subject | TEXT | |
| detail_json | TEXT | |
| prev_hash / entry_hash | TEXT | hash chain for tamper evidence |

## Relationships (summary)

```
scan_jobs 1─* file_scans *─1 files
file_scans 1─* engine_runs 1─* detections
file_scans *─1 verdicts 1─* manual_reviews
verdicts 1─* quarantine_items
security_events *─* alerts (via JSON id list, kept denormalized deliberately)
```

## Integrity rules
- Deleting a `scan_jobs` row cascades to its `file_scans`, `engine_runs` and `detections`; `files`, `verdicts`, `quarantine_items` and `audit_log` are never cascaded away.
- `audit_log` is insert-only in application code; a startup check re-verifies the hash chain and reports breaks.
- Retention is user-configured and only prunes `security_events` and old scan history, never quarantine or audit data.
