#!/usr/bin/env python3
"""Write a human-readable summary from results.jsonl."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    results_path = root / "results.jsonl"
    progress = json.loads((root / "progress.json").read_text(encoding="utf-8")) if (root / "progress.json").exists() else {}
    verdicts = Counter()
    products_vuln: dict[str, list[str]] = {}
    critical_rows = []
    failed = []
    if results_path.exists():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            verdicts[row.get("verdict") or "unknown"] += 1
            if row.get("status") == "failed":
                failed.append(row)
            if row.get("verdict") in {"vulnerable", "likely_vulnerable"}:
                products_vuln.setdefault(row["product"], []).append(
                    f"{row.get('version')} ({row.get('worst_severity')})"
                )
            if row.get("worst_severity") == "critical":
                critical_rows.append(row)

    lines = [
        "# Wallet extension weak-RNG audit",
        "",
        f"- Progress: **{progress.get('percent', 0)}%** ({progress.get('done', 0)}/{progress.get('total', 0)})",
        f"- Vulnerable or likely: **{progress.get('vulnerable_or_likely', 0)}**",
        f"- Failed downloads/unpacks: **{progress.get('failed', 0)}**",
        "",
        "## Verdicts",
        "",
    ]
    for name, count in verdicts.most_common():
        lines.append(f"- `{name}`: {count}")
    lines += ["", "## Critical / likely products", ""]
    if not products_vuln:
        lines.append("None yet.")
    else:
        for product, versions in sorted(products_vuln.items()):
            shown = ", ".join(versions[:8])
            extra = f" … +{len(versions) - 8}" if len(versions) > 8 else ""
            lines.append(f"- **{product}**: {shown}{extra}")
    lines += ["", "## Critical samples", ""]
    if not critical_rows:
        lines.append("None yet.")
    else:
        for row in critical_rows[:40]:
            lines.append(
                f"- `{row['id']}` {row['product']} {row.get('version')} "
                f"findings={row.get('finding_count')} file={row.get('findings_file', '')}"
            )
    lines += ["", "## Failed", ""]
    if not failed:
        lines.append("None.")
    else:
        for row in failed[:40]:
            lines.append(f"- `{row['id']}` {row['product']} {row.get('version')}: {row.get('error')}")
    (root / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print((root / "SUMMARY.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
