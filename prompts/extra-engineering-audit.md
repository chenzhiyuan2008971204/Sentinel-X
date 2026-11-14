Perform a complete engineering audit of Sentinel X.

Do not add new features.

Inspect the entire current implementation.

Check:
- Broken imports.
- Missing dependencies.
- Incorrect Windows paths.
- Unimplemented functions.
- Fake GUI interactions.
- Incorrect detection classifications.
- Database inconsistencies.
- Unsafe quarantine operations.
- Resource leaks.
- Threading problems.
- Incorrect exception handling.
- Missing tests.
- Security vulnerabilities.

Run the complete test suite.
Fix confirmed defects.
Do not hide failing tests.
Do not downgrade tests to make them pass.

Generate an ENGINEERING_AUDIT.md documenting:
- Findings
- Severity
- Root cause
- Fixes
- Remaining issues
- Test results
