"""Build the Windows package: PyInstaller folder + bundled ClamAV + notices, then the installer.

    python packaging/build.py [--clamav-dir "C:\\Program Files\\ClamAV"] [--no-installer]

Steps
1. Write the Windows version resource from `sentinelx.__version__`.
2. PyInstaller one-folder build -> dist/SentinelX.
3. Copy the ClamAV runtime (executables, DLLs, certificates, license files — no debug
   symbols, import libraries or headers) to dist/SentinelX/clamav, with SOURCE.txt naming the
   exact upstream source (GPLv2 requires the source to be available).
4. Write THIRD_PARTY_NOTICES.txt.
5. Check the build: the frozen app starts and exits (smoke test), the isolated research worker
   answers in JSON from the windowed executable, and the bundled clamscan reports its version.
6. Compile the installer with Inno Setup (ISCC.exe) if it is installed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
APP = DIST / "SentinelX"
CLAMAV_FILES = ("clamscan.exe", "clamd.exe", "freshclam.exe", "COPYING.txt", "README.md", "NEWS.md")
CLAMAV_DIRS = ("certs", "COPYING")
ISCC_CANDIDATES = (
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Inno Setup 6" / "ISCC.exe",
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Inno Setup 6" / "ISCC.exe",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
)
NOTICES = """Sentinel X — third-party components

Sentinel X is distributed with the following components. Each keeps its own license.

ClamAV {clamav} — GNU General Public License v2 (clamav\\COPYING.txt, clamav\\COPYING\\).
  Shipped unmodified as separate programs in the clamav folder. Source: see clamav\\SOURCE.txt.
Qt 6 / PySide6 6.8.1 — GNU Lesser General Public License v3. Shipped as unmodified shared
  libraries (PySide6\\*.dll, Qt6*.dll) that can be replaced. Source: https://download.qt.io/
Python 3.12 — Python Software Foundation License.
SQLAlchemy 2.0.36 (MIT), pydantic 2.10.3 (MIT), yara-python 4.5.1 / libyara (Apache-2.0, BSD-3),
pefile 2024.8.26 (MIT), psutil 6.1.0 (BSD-3), watchdog 6.0.0 (Apache-2.0), Jinja2 3.1.4 (BSD-3),
MarkupSafe 3.0.4 (BSD-3), ReportLab 4.2.5 (BSD-3), pillow 13.0.0 (MIT-CMU), chardet 7.7.0 (LGPLv2.1).

PDF reports embed a subset of a Chinese font installed on the computer (Microsoft JhengHei by
default); no font is redistributed with this build.
"""


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    print("+", " ".join(cmd))
    return subprocess.run(cmd, check=True, **kw)


def version() -> str:
    sys.path.insert(0, str(ROOT / "src"))
    from sentinelx import __version__

    return __version__


def write_version_info(v: str) -> None:
    nums = [int(x) for x in re.findall(r"\d+", v)[:3]] + [0]
    t = ", ".join(str(n) for n in (nums + [0, 0, 0, 0])[:4])
    (ROOT / "packaging" / "version_info.txt").write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({t}), prodvers=({t}), mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040404b0', [
      StringStruct('CompanyName', 'Sentinel X project'),
      StringStruct('FileDescription', 'Sentinel X Research Edition'),
      StringStruct('FileVersion', '{v}'),
      StringStruct('InternalName', 'SentinelX'),
      StringStruct('OriginalFilename', 'SentinelX.exe'),
      StringStruct('ProductName', 'Sentinel X'),
      StringStruct('ProductVersion', '{v}')])]),
    VarFileInfo([VarStruct('Translation', [1028, 1200])])]
)
""", encoding="utf-8")


def copy_clamav(src: Path) -> str:
    dest = APP / "clamav"
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for name in CLAMAV_FILES:
        shutil.copy2(src / name, dest / name)
    for dll in src.glob("*.dll"):
        shutil.copy2(dll, dest / dll.name)
    for d in CLAMAV_DIRS:
        shutil.copytree(src / d, dest / d)
    out = subprocess.run([str(dest / "clamscan.exe"), "--version"], capture_output=True, text=True, timeout=60)
    m = re.match(r"ClamAV\s+([0-9.]+)", out.stdout.strip())
    if not m:
        raise SystemExit(f"bundled clamscan did not report a version: {out.stdout!r} {out.stderr!r}")
    ver = m.group(1)
    (dest / "SOURCE.txt").write_text(
        f"ClamAV {ver} (Cisco Talos), shipped unmodified under the GNU GPL v2 (see COPYING.txt).\n"
        f"Corresponding source code: https://github.com/Cisco-Talos/clamav/tree/clamav-{ver}\n"
        f"Release archive: https://www.clamav.net/downloads\n"
        f"Copied from: {src}\n", encoding="utf-8")
    return ver


def check_build(clamav_version: str) -> None:
    exe = APP / "SentinelX.exe"
    home = Path(tempfile.mkdtemp(prefix="sx-build-check-"))
    env = {**os.environ, "SENTINELX_HOME": str(home), "QT_QPA_PLATFORM": "offscreen"}
    rc = subprocess.run([str(exe), "--smoke-test", "1500"], env=env, timeout=180).returncode
    if rc != 0:
        raise SystemExit(f"frozen smoke test failed with exit code {rc}")
    print("smoke test: ok")
    # The windowed executable must answer the research worker protocol on its stdout handle (R14).
    with tempfile.TemporaryFile() as out:
        rc = subprocess.run([str(exe), "--research-worker", str(exe), str(500 * 1024 * 1024)], stdout=out,
                            stdin=subprocess.DEVNULL, timeout=120).returncode
        out.seek(0)
        data = json.loads(out.read().decode("utf-8"))
    if rc != 0 or not data.get("ok") or not data.get("confined"):
        raise SystemExit(f"frozen research worker failed: rc={rc} {data}")
    print("research worker:", data["pe"]["engine_version"], "| signature", data["signature"]["status"],
          "| confined", data["confined"])
    v = subprocess.run([str(APP / "clamav" / "clamscan.exe"), "--version"], capture_output=True, text=True,
                       timeout=60).stdout.strip()
    if clamav_version not in v:
        raise SystemExit(f"bundled clamscan version mismatch: {v}")
    print("bundled ClamAV:", v)
    shutil.rmtree(home, ignore_errors=True)


def build_installer(v: str) -> Path | None:
    iscc = next((p for p in ISCC_CANDIDATES if p.is_file()), None)
    if iscc is None:
        print("Inno Setup (ISCC.exe) not found: installer not built.")
        return None
    run([str(iscc), f"/DAppVersion={v}", f"/DSourceDir={APP}", f"/DOutputDir={DIST}",
         str(ROOT / "packaging" / "installer.iss")])
    return DIST / f"SentinelX-{v}-setup.exe"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clamav-dir", default=str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV"))
    ap.add_argument("--no-installer", action="store_true")
    ap.add_argument("--dist", help="output folder (default: dist in the project). Use a folder outside "
                    "Desktop/Documents/Downloads when Sentinel X's execution lock is on: it locks the new "
                    "programs there until they are scanned, which breaks the build's own start test.")
    args = ap.parse_args()
    global DIST, APP
    if args.dist:
        DIST = Path(args.dist).resolve()
        APP = DIST / "SentinelX"
    v = version()
    write_version_info(v)
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", str(DIST),
         "--workpath", str(ROOT / "build" / "pyinstaller"), str(ROOT / "packaging" / "sentinelx.spec")])
    clamav_version = copy_clamav(Path(args.clamav_dir))
    (APP / "THIRD_PARTY_NOTICES.txt").write_text(NOTICES.format(clamav=clamav_version), encoding="utf-8")
    check_build(clamav_version)
    if not args.no_installer:
        out = build_installer(v)
        if out:
            print("installer:", out)
    print("done:", APP)


if __name__ == "__main__":
    main()
