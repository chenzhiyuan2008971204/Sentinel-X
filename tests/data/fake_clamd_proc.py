"""Stand-in for clamd.exe in tests: a process that speaks zVERSION / zINSTREAM.

Reads TCPSocket from --config-file. FAKE_CLAMD_DELAY delays readiness (simulates loading
signatures); FAKE_CLAMD_MODE=crash exits at once.
"""

import os
import socket
import struct
import sys
import threading
import time

MARKER = b"SX-TEST-MALWARE-MARKER"
conf = next(a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--config-file="))
port = None
with open(conf, encoding="utf-8") as f:
    for line in f:
        if line.startswith("TCPSocket "):
            port = int(line.split()[1])
if os.environ.get("FAKE_CLAMD_MODE") == "crash":
    sys.exit(7)
time.sleep(float(os.environ.get("FAKE_CLAMD_DELAY", "0")))
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", port))
srv.listen(16)


def handle(conn):  # type: ignore[no-untyped-def]
    with conn:
        cmd = b""
        while not cmd.endswith(b"\0"):
            b = conn.recv(1)
            if not b:
                return
            cmd += b
        if cmd == b"zVERSION\0":
            conn.sendall(b"ClamAV 1.5.4/28171/Mon Nov  2 09:00:00 2026\0")
            return
        data = bytearray()
        while True:
            hdr = b""
            while len(hdr) < 4:
                chunk = conn.recv(4 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            (n,) = struct.unpack("!L", hdr)
            if n == 0:
                break
            while n:
                chunk = conn.recv(min(n, 65536))
                if not chunk:
                    return
                data += chunk
                n -= len(chunk)
        conn.sendall(b"stream: Sentinel.Test.Marker-1 FOUND\0" if MARKER in data else b"stream: OK\0")


while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
