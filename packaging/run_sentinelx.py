"""PyInstaller entry point for the packaged Sentinel X."""

import sys

from sentinelx.app.main import main

if __name__ == "__main__":
    sys.exit(main())
