#!/usr/bin/env python3
"""Download the next N pending packages and unpack them for live agent audit."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from orchestrator import (
    BATCH_SIZE,
    already_done_ids,
    download,
    load_json,
    pending_tasks,
    save_json,
    sha256_file,
    unpack_package,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", default="wallet-rng-audit/catalog.json")
    parser.add_argument("--results", default="wallet-rng-audit/results.jsonl")
    parser.add_argument("--hold", default="/tmp/wallet-rng-hold")
    parser.add_argument("--size", type=int, default=BATCH_SIZE)
    args = parser.parse_args()

    catalog = load_json(Path(args.catalog), None)
    if not catalog:
        print("missing catalog", file=sys.stderr)
        return 1
    done = already_done_ids(Path(args.results))
    hold_root = Path(args.hold)
    if hold_root.exists():
        shutil.rmtree(hold_root)
    hold_root.mkdir(parents=True)
    batch = pending_tasks(catalog, done)[: args.size]
    manifest = []
    for task in batch:
        task_dir = hold_root / task["id"]
        task_dir.mkdir(parents=True)
        pkg = task_dir / "package.bin"
        size, err = download(task["url"], pkg)
        row = {**task, "dir": str(task_dir), "unpacked": str(task_dir / "unpacked")}
        if err:
            row.update({"status": "failed", "error": err})
            print(f"FAIL {task['id']}: {err}")
        else:
            try:
                unpack_package(pkg.read_bytes(), task_dir)
                row.update(
                    {
                        "status": "ready",
                        "bytes": size,
                        "sha256": sha256_file(pkg),
                    }
                )
                print(f"READY {task['product']} {task['version']} -> {task_dir}")
            except Exception as exc:  # noqa: BLE001
                row.update({"status": "failed", "error": f"unpack: {exc}"})
                print(f"FAIL {task['id']}: unpack {exc}")
        manifest.append(row)
    dest = hold_root / "manifest.json"
    save_json(dest, {"batch_size": len(manifest), "tasks": manifest})
    print(json.dumps({"manifest": str(dest), "ready": sum(1 for t in manifest if t.get("status") == "ready")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
