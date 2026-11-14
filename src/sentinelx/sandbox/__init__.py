"""Trial-run room: run a file inside a disposable VirtualBox virtual machine and watch what it does.

Nothing is ever executed on the host. The VM has no network adapter, is restored to a clean
snapshot before and after every run, and is rebuilt from the saved Windows evaluation ISO before
the 90-day evaluation runs out.
"""

# Engineering audit 8 (H3) kept this off until a real build and the four harmless test runs passed
# end to end. Passed on the user's computer on 2026-11-08 (Windows 11 Enterprise evaluation 26300,
# VirtualBox 7.2.22): quiet -> no findings, persist -> run key + dropped program, decoys -> 40 of
# 40 changed (strong), EICAR -> Defender detection (strong). False keeps the page disabled.
FINISHED = True
