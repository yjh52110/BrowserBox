#!/usr/bin/env python3
"""Download 10 wallet packages, scan for weak RNG, delete files, repeat."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scan_weak_rng import scan_unpacked

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
BATCH_SIZE = 10
MAX_DOWNLOAD_BYTES = 80 * 1024 * 1024


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def crx_zip_offset(data: bytes) -> int:
    if len(data) >= 4 and data[:4] == b"Cr24":
        version = int.from_bytes(data[4:8], "little")
        if version == 2 and len(data) >= 16:
            pub = int.from_bytes(data[8:12], "little")
            sig = int.from_bytes(data[12:16], "little")
            return 16 + pub + sig
        if version == 3 and len(data) >= 12:
            header = int.from_bytes(data[8:12], "little")
            return 12 + header
    loc = data.find(b"PK\x03\x04")
    return loc if loc >= 0 else 0


def unpack_package(blob: bytes, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    offset = crx_zip_offset(blob)
    zip_bytes = blob[offset:]
    zip_path = dest / "_package.zip"
    zip_path.write_bytes(zip_bytes)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(dest / "unpacked")
    finally:
        zip_path.unlink(missing_ok=True)


def download(url: str, dest: Path, timeout: int = 60) -> tuple[int, str | None]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
            if len(data) > MAX_DOWNLOAD_BYTES:
                return 0, "file too large"
            dest.write_bytes(data)
            return len(data), None
    except HTTPError as exc:
        return 0, f"HTTP {exc.code}"
    except (URLError, TimeoutError, OSError) as exc:
        return 0, str(exc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_progress(progress_path: Path, catalog_total: int, results_path: Path) -> dict:
    done = 0
    vulnerable = 0
    failed = 0
    if results_path.exists():
        with results_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                done += 1
                row = json.loads(line)
                if row.get("status") == "failed":
                    failed += 1
                if row.get("verdict") in {"vulnerable", "likely_vulnerable"}:
                    vulnerable += 1
    percent = round(100.0 * done / catalog_total, 2) if catalog_total else 0.0
    progress = {
        "total": catalog_total,
        "done": done,
        "failed": failed,
        "vulnerable_or_likely": vulnerable,
        "percent": percent,
        "updated_at": int(time.time()),
    }
    save_json(progress_path, progress)
    return progress


def already_done_ids(results_path: Path) -> set[str]:
    ids: set[str] = set()
    if not results_path.exists():
        return ids
    with results_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ids.add(json.loads(line)["id"])
    return ids


def append_result(results_path: Path, row: dict) -> None:
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def process_task(task: dict, work_dir: Path, findings_dir: Path, cache: dict) -> dict:
    task_dir = work_dir / task["id"]
    if task_dir.exists():
        shutil.rmtree(task_dir, ignore_errors=True)
    task_dir.mkdir(parents=True)
    url = task["url"]
    cache_hit = cache.get(url)
    started = time.time()
    try:
        if cache_hit:
            result = {
                **task,
                "status": cache_hit.get("status", "ok"),
                "deduped_from": cache_hit.get("id"),
                "sha256": cache_hit.get("sha256"),
                "bytes": cache_hit.get("bytes"),
                "verdict": cache_hit.get("verdict"),
                "worst_severity": cache_hit.get("worst_severity"),
                "finding_count": cache_hit.get("finding_count", 0),
                "severity_counts": cache_hit.get("severity_counts", {}),
                "error": cache_hit.get("error"),
                "elapsed_sec": round(time.time() - started, 3),
                "deleted": True,
            }
            if cache_hit.get("findings_file"):
                src = Path(cache_hit["findings_file"])
                dest = findings_dir / f"{task['id']}.json"
                if src.exists():
                    dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                    result["findings_file"] = str(dest)
            return result

        pkg = task_dir / "package.bin"
        size, err = download(url, pkg)
        if err:
            result = {
                **task,
                "status": "failed",
                "error": err,
                "verdict": "download_failed",
                "elapsed_sec": round(time.time() - started, 3),
                "deleted": True,
            }
            cache[url] = result
            return result

        digest = sha256_file(pkg)
        blob = pkg.read_bytes()
        try:
            unpack_package(blob, task_dir)
        except (zipfile.BadZipFile, OSError) as exc:
            result = {
                **task,
                "status": "failed",
                "error": f"unpack: {exc}",
                "sha256": digest,
                "bytes": size,
                "verdict": "unpack_failed",
                "elapsed_sec": round(time.time() - started, 3),
                "deleted": True,
            }
            cache[url] = result
            return result

        scan = scan_unpacked(task_dir / "unpacked")
        findings_path = findings_dir / f"{task['id']}.json"
        save_json(
            findings_path,
            {
                "id": task["id"],
                "product": task["product"],
                "version": task["version"],
                "url": url,
                "sha256": digest,
                **scan,
            },
        )
        result = {
            **task,
            "status": "ok",
            "sha256": digest,
            "bytes": size,
            "verdict": scan["verdict"],
            "worst_severity": scan["worst_severity"],
            "finding_count": scan["finding_count"],
            "severity_counts": scan["severity_counts"],
            "findings_file": str(findings_path),
            "elapsed_sec": round(time.time() - started, 3),
            "deleted": True,
        }
        cache[url] = result
        return result
    finally:
        shutil.rmtree(task_dir, ignore_errors=True)


def pending_tasks(catalog: dict, done: set[str]) -> list[dict]:
    return [t for t in catalog["tasks"] if t["id"] not in done]


def run_batches(args: argparse.Namespace) -> int:
    catalog = load_json(Path(args.catalog), None)
    if not catalog:
        print("missing catalog", file=sys.stderr)
        return 1
    results_path = Path(args.results)
    progress_path = Path(args.progress)
    findings_dir = Path(args.findings)
    work_dir = Path(args.work)
    findings_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    done = already_done_ids(results_path)
    cache: dict = {}
    pending = pending_tasks(catalog, done)
    total = catalog["total"]
    batch_limit = args.batches
    processed_batches = 0

    print(f"catalog={total} done={len(done)} pending={len(pending)} batch_size={BATCH_SIZE}")
    while pending:
        batch = pending[:BATCH_SIZE]
        processed_batches += 1
        print(
            f"\n=== batch {processed_batches} download={len(batch)} "
            f"progress={len(done)}/{total} ({100.0 * len(done) / total:.2f}%) ===",
            flush=True,
        )
        for task in batch:
            print(f"  audit {task['product']} {task['version']} ...", flush=True)
            row = process_task(task, work_dir, findings_dir, cache)
            append_result(results_path, row)
            done.add(task["id"])
            print(
                f"    {row.get('status')} verdict={row.get('verdict')} "
                f"findings={row.get('finding_count', 0)} deleted={row.get('deleted')}",
                flush=True,
            )
        progress = write_progress(progress_path, total, results_path)
        print(
            f"  batch complete {progress['percent']}% "
            f"vulnerable_or_likely={progress['vulnerable_or_likely']} "
            f"failed={progress['failed']}",
            flush=True,
        )
        pending = pending_tasks(catalog, done)
        if batch_limit and processed_batches >= batch_limit:
            break
    progress = write_progress(progress_path, total, results_path)
    print(json.dumps(progress, ensure_ascii=False), flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", default="wallet-rng-audit/catalog.json")
    parser.add_argument("--results", default="wallet-rng-audit/results.jsonl")
    parser.add_argument("--progress", default="wallet-rng-audit/progress.json")
    parser.add_argument("--findings", default="wallet-rng-audit/findings")
    parser.add_argument("--work", default="/tmp/wallet-rng-work")
    parser.add_argument("--batches", type=int, default=0, help="0 = until 100%")
    args = parser.parse_args()
    return run_batches(args)


if __name__ == "__main__":
    raise SystemExit(main())
