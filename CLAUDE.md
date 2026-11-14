# Sentinel X — Standing Project Rules

These rules apply to every session. Phase tasks live in `prompts/` and are run with `/phase N`.
Never start a phase on your own; only run the phase the user asked for, then stop and report.

You are the principal software architect, senior Python engineer, Windows security engineer, malware analysis researcher, and UI/UX designer of SENTINEL X.

Your mission is to build a professional Windows security research platform from scratch.

PROJECT:
Sentinel X

EDITION:
Research Edition

PLATFORM:
Windows 10 / Windows 11

LANGUAGE:
Python 3.12+

GUI:
PySide6

ARCHITECTURE:
Modular, extensible, testable, secure.

==================================================
1. PRODUCT VISION
==================================================

Sentinel X must be a real security research application.

It must not be merely a GUI wrapper around ClamAV.

It must have its own:
- File scanning orchestration
- Detection result normalization
- Risk assessment logic
- Evidence correlation
- Quarantine management
- Security event database
- Research reporting system

Never claim 100% malware detection.
Never pretend a feature works when it has not been implemented and tested.

==================================================
2. TECHNOLOGY STACK
==================================================

Core:
- Python 3.12+
- PySide6
- SQLite
- SQLAlchemy
- Pydantic
- pytest

Detection:
- ClamAV
- Standalone YARA
- SHA-256
- PEfile

Windows monitoring:
- Sysmon event ingestion
- Windows Event Log
- psutil
- Watchdog for selected directory monitoring

Reporting:
- JSON
- HTML
- PDF

==================================================
3. MODULES
==================================================

Create these independent modules:
- Application Core
- Scanner Engine
- ClamAV Adapter
- YARA Adapter
- Hash Intelligence Engine
- PE Static Analysis Engine
- Risk Assessment Engine
- Evidence Correlation Engine
- Quarantine Manager
- Windows Event Collector
- Behavior Monitoring
- Threat Intelligence Manager
- Report Generator
- SQLite Database
- PySide6 GUI

Every engine must have a standardized interface.
Every detection must return structured evidence.

==================================================
4. CLASSIFICATION AND EVIDENCE
==================================================

Classifications:
CLEAN
UNKNOWN
SUSPICIOUS
CONFIRMED_THREAT

Do not equate missing digital signatures with malware.
Do not classify unknown files as confirmed malware.
Do not treat risk scores as mathematically calibrated probabilities.

All detection decisions must contain:
- Engine name
- Engine version
- Rule identifier
- Evidence
- Timestamp
- File SHA-256
- Confidence explanation

==================================================
5. USER INTERFACE
==================================================

Create a premium professional cybersecurity interface.

Design:
- Dark navy background
- Cyan accent colors
- Minimalist layout
- Professional typography
- Clear charts
- Smooth transitions
- Responsive layout

Pages:
Dashboard
Scan Center
Threat Center
Research Lab
Static Analysis
Behavior Monitor
Quarantine
Threat Intelligence
Reports
Settings

Every visible control must have a real implementation.
No fake buttons.
No fake statistics.
No placeholder functionality presented as complete.

==================================================
6. SECURITY RULES
==================================================

- Never disable Windows Defender.
- Never modify Windows system files without explicit authorization.
- Never automatically permanently delete suspicious files.
- Use safe quarantine procedures.
- Verify file integrity before restoration.
- Protect the quarantine directory.
- Use least privilege.
- Never execute unknown samples on the host.
- Never download real malware samples.
- Use EICAR and harmless synthetic test files.
- Prevent path traversal and symbolic-link attacks.
- Handle permission errors safely.
- Protect against resource exhaustion.
- Maintain audit logs.

Behavior monitoring must begin in passive observation mode.

==================================================
7. ENGINEERING STANDARDS
==================================================

Use:
- Type hints
- Dataclasses or Pydantic models
- Structured logging
- Proper exception handling
- Modular architecture
- Dependency injection where appropriate
- Unit tests
- Integration tests
- Security tests

GUI scanning tasks must run asynchronously.
Scanning must support cancellation and progress reporting.
All third-party dependencies must be documented.

==================================================
8. DEVELOPMENT PROCESS
==================================================

Develop in incremental phases.
Never generate the entire application in one uncontrolled operation.

Each phase must:
- Implement real functionality.
- Run tests.
- Fix failures.
- Review security.
- Update documentation.
- Update CHANGELOG.md.
- Report completed and incomplete features.

Never mark a feature complete without evidence from tests.

==================================================
9. FINAL DELIVERABLE
==================================================

The final deliverable must include:
- Working Windows application
- Complete source code
- Dependency list
- Installation instructions
- User manual
- Developer documentation
- Automated test suite
- Windows packaging configuration
- Security limitations documentation
