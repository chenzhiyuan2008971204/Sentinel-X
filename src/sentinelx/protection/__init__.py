"""Real-time protection (user mode).

What it does: scans files soon after they are written in the watched places (Downloads,
Desktop, Documents, the temporary folder, removable drives), quarantines confirmed threats if
the user allowed it, terminates processes started from a confirmed or quarantined threat, and
alerts on changes to the quarantine vault that Sentinel X did not make.

What it cannot do: stop a program before Windows starts it, or see which process reads a file.
Both need a signed kernel driver. Windows Defender remains the first line of defence.
"""
