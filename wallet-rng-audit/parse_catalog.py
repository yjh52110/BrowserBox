#!/usr/bin/env python3
"""Parse CRX_WALLET_DOWNLOAD_LINKS markdown into a JSON task catalog."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROW_RE = re.compile(
    r"^\| `(?P<version>[^`]+)` \| (?P<kind>[^|]+) \| <(?P<url>https?://[^>]+)> \|"
)
HEADING_RE = re.compile(r"^## (?P<name>.+)$")


def parse_catalog(md_path: Path) -> list[dict]:
    product = None
    tasks: list[dict] = []
    in_toc = False
    for line in md_path.read_text(encoding="utf-8").splitlines():
        heading = HEADING_RE.match(line)
        if heading:
            name = heading.group("name").strip()
            if name in {"统计", "目录"}:
                in_toc = name == "目录"
                product = None
                continue
            in_toc = False
            product = name
            continue
        if in_toc or not product:
            continue
        row = ROW_RE.match(line)
        if not row:
            continue
        version = row.group("version").strip()
        kind = row.group("kind").strip()
        url = row.group("url").strip()
        task_id = f"{_slug(product)}__{_slug(version)}__{len(tasks):04d}"
        tasks.append(
            {
                "id": task_id,
                "product": product,
                "version": version,
                "kind": kind,
                "url": url,
            }
        )
    return tasks


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return slug[:80] or "item"


def main() -> int:
    src = Path(sys.argv[1])
    dest = Path(sys.argv[2])
    tasks = parse_catalog(src)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"total": len(tasks), "tasks": tasks}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"parsed {len(tasks)} tasks -> {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
