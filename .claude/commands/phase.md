---
description: Run one Sentinel X development phase (0 = architecture docs, 1-9 = build phases)
argument-hint: [0-9]
---
Use Glob to find the file in `prompts/` whose name starts with `phase-$ARGUMENTS-`.
Read it completely and execute it exactly, following the standing rules in CLAUDE.md.
Run the tests for this phase and fix failures before reporting.
When finished, give a completion report (done / not done / test results) and STOP.
Do not begin the next phase.
