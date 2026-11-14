# PyInstaller spec for Sentinel X (one-folder, windowed). Build with `python packaging/build.py`.
# One-folder instead of one-file: no unpacking to %TEMP% at every start, faster start, and
# fewer antivirus false positives than self-extracting executables.
# ruff: noqa
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

ROOT = Path(SPECPATH).parent
SRC = ROOT / "src"

datas = collect_data_files("sentinelx", includes=["resources/*.xml", "resources/fonts/*", "reporting/templates/*.j2", "sandbox/*.ps1"])
# importlib.metadata versions are written into reports (tool versions).
for dist in ("sentinelx", "pefile", "yara-python", "PySide6", "SQLAlchemy", "Jinja2", "reportlab", "psutil",
             "watchdog", "pydantic"):
    datas += copy_metadata(dist)

a = Analysis(
    [str(ROOT / "packaging" / "run_sentinelx.py")],
    pathex=[str(SRC)],
    datas=datas,
    hiddenimports=[
        "sentinelx.research.worker",          # started as `SentinelX.exe --research-worker`
        "sqlalchemy.dialects.sqlite.pysqlite",
        "watchdog.observers.read_directory_changes",
    ],
    excludes=["tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore",
              "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtMultimedia", "PySide6.QtCharts",
              "pytest", "pytestqt", "pypdf"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SentinelX",
    console=False,                 # windowed GUI application
    upx=False,                     # UPX-packed binaries are a common antivirus false-positive trigger
    version=str(ROOT / "packaging" / "version_info.txt"),
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="SentinelX")
