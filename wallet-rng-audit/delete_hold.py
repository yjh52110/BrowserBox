#!/usr/bin/env python3
"""Delete held packages after agent audit completes."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def main() -> int:
    hold = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/wallet-rng-hold")
    if hold.exists():
        shutil.rmtree(hold)
        print(f"deleted {hold}")
    else:
        print(f"already gone: {hold}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
