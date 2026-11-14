"""A stand-in for clamscan.exe used by tests. Harmless: it only reads files and prints.

Behaviour is selected with SX_FAKE_CLAM_MODE:
  normal  - versions with DB, per-file OK/FOUND/ERROR lines
  nodb    - `--version` prints only the engine version (no signature DB)
  crash   - exit code 50 with a message on stderr
  hang    - sleep for a long time (timeout / cancel tests)
  garbage - print unparseable output, exit 0
  partial - omit the result line for the last file
"""

import os
import sys
import time

MODE = os.environ.get("SX_FAKE_CLAM_MODE", "normal")
EICAR_HEAD = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
MARKER = b"SX-TEST-MALWARE-MARKER"
LIMITS = b"SX-TEST-LIMITS"

out = sys.stdout.buffer


def emit(s: str) -> None:
    out.write((s + "\n").encode("utf-8"))


args = sys.argv[1:]
if "--version" in args:
    emit("ClamAV 1.5.4" if MODE == "nodb" else "ClamAV 1.5.4/27800/Sun Nov  1 09:00:00 2026")
    sys.exit(0)

if MODE == "crash":
    sys.stderr.write("LibClamAV Error: simulated crash\n")
    sys.exit(50)
if MODE == "hang":
    time.sleep(120)
    sys.exit(0)
if MODE == "garbage":
    emit("this is not clamscan output")
    sys.exit(0)

list_arg = next(a for a in args if a.startswith("--file-list="))
with open(list_arg.split("=", 1)[1], encoding="utf-8") as f:
    paths = [line.rstrip("\n") for line in f if line.strip()]
if MODE == "partial":
    paths = paths[:-1]

found = errors = False
for p in paths:
    try:
        with open(p, "rb") as fh:
            data = fh.read()
    except OSError:
        emit(f"{p}: Can't open file or directory ERROR")
        errors = True
        continue
    if not data:
        emit(f"{p}: Empty file")
    elif EICAR_HEAD in data:
        emit(f"{p}: Eicar-Test-Signature FOUND")
        found = True
    elif LIMITS in data:
        emit(f"{p}: Heuristics.Limits.Exceeded.MaxFileSize FOUND")
        found = True
    elif MARKER in data:
        emit(f"{p}: Sentinel.Test.Marker-1 FOUND")
        found = True
    else:
        emit(f"{p}: OK")
sys.exit(1 if found else (2 if errors else 0))
