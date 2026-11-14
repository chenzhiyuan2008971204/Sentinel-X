"""Stand-in for freshclam.exe in tests: never touches the network.

Reads DatabaseDirectory from --config-file and writes small placeholder .cvd files there.
FAKE_FRESHCLAM_MODE=fail exits 1; =slow sleeps (for cancellation tests).
"""

import os
import sys
import time

conf = next(a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--config-file="))
db = None
with open(conf, encoding="utf-8") as f:
    for line in f:
        if line.startswith("DatabaseDirectory "):
            db = line.split(" ", 1)[1].strip()
mode = os.environ.get("FAKE_FRESHCLAM_MODE", "")
print("ClamAV update process started (fake)")
if mode == "slow":
    time.sleep(60)
if mode == "fail":
    print("ERROR: Can't download daily.cvd from database.clamav.net (fake)")
    sys.exit(1)
for name in ("main.cvd", "daily.cvd", "bytecode.cvd"):
    with open(os.path.join(db, name), "wb") as f:
        f.write(b"ClamAV-VDB:fake-test-signature-placeholder")
    print(f"{name} updated (fake)")
