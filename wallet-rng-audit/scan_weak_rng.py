#!/usr/bin/env python3
"""Static weak-RNG scanner for unpacked wallet extensions."""

from __future__ import annotations

import json
import re
from pathlib import Path

SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    "__MACOSX",
}
TEXT_SUFFIXES = {
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".html",
    ".htm",
    ".json",
    ".map",
    ".vue",
    ".svelte",
}
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_HITS_PER_PATTERN = 8
CONTEXT = 160

CRYPTO_HINTS = re.compile(
    r"private[_-]?key|mnemonic|bip39|hdkey|entropy|seedphrase|seed[_-]?phrase|"
    r"secret[_-]?key|signing[_-]?key|wallet|iv\b|nonce|salt|aes|cipher|"
    r"getrandomvalues|randombytes|pbkdf|scrypt|argon|ecdsa|secp256|"
    r"keypair|generatekey|createwallet|fromentropy|frommnemonic",
    re.I,
)
UI_HINTS = re.compile(
    r"testid|className|css|color|width|height|animation|opacity|zIndex|"
    r"tooltip|uuidv?4|requestId|messageId|tabId",
    re.I,
)

PATTERNS = [
    {
        "id": "math_random",
        "severity_base": "medium",
        "re": re.compile(r"Math\.random\s*\("),
        "title": "Math.random() — not CSPRNG",
    },
    {
        "id": "date_now_seed",
        "severity_base": "high",
        "re": re.compile(
            r"(?:Math\.seedrandom|seedrandom|setSeed|prng|LCG|mersenne|mt19937|"
            r"createRng|new\s+Random)\s*\([^)]{0,80}(?:Date\.now|new\s+Date|\+new Date)",
            re.I,
        ),
        "title": "PRNG seeded from Date/time",
    },
    {
        "id": "timestamp_entropy",
        "severity_base": "high",
        "re": re.compile(
            r"(?:entropy|seed|rngSeed|randomSeed)\s*[:=]\s*(?:Date\.now\(\)|\+new Date|"
            r"performance\.now\(\)|new Date\(\)\.getTime\(\))",
            re.I,
        ),
        "title": "Timestamp used as entropy/seed",
    },
    {
        "id": "seedrandom",
        "severity_base": "high",
        "re": re.compile(r"seedrandom|Math\.seedrandom"),
        "title": "seedrandom / seeded PRNG",
    },
    {
        "id": "pseudo_random_bytes",
        "severity_base": "critical",
        "re": re.compile(r"pseudoRandomBytes|crypto\.pseudoRandomBytes"),
        "title": "crypto.pseudoRandomBytes",
    },
    {
        "id": "insecure_uuid",
        "severity_base": "medium",
        "re": re.compile(r"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx|s4\(\)\s*\+\s*s4\(\)"),
        "title": "UUID built from Math.random-style nibble fill",
    },
    {
        "id": "chance_js",
        "severity_base": "medium",
        "re": re.compile(r"new\s+Chance\s*\(|require\(\s*['\"]chance['\"]"),
        "title": "Chance.js PRNG",
    },
    {
        "id": "mersenne",
        "severity_base": "high",
        "re": re.compile(r"MersenneTwister|mt19937|Twister\s*\("),
        "title": "Mersenne Twister PRNG",
    },
    {
        "id": "lcg",
        "severity_base": "high",
        "re": re.compile(r"16807|2147483647\s*\*|1103515245|1664525"),
        "title": "Linear congruential generator constants",
    },
    {
        "id": "fixed_seed",
        "severity_base": "critical",
        "re": re.compile(r"(?:setSeed|seedrandom|createPRNG|seed\s*:)\s*\(\s*['\"]?\d{3,}['\"]?\s*\)"),
        "title": "Hardcoded / numeric PRNG seed",
    },
    {
        "id": "bip39_no_rng",
        "severity_base": "high",
        "re": re.compile(r"generateMnemonic\s*\(\s*(?:12|15|18|21|24|128|256)?\s*\)"),
        "title": "bip39.generateMnemonic without explicit CSPRNG",
    },
    {
        "id": "math_random_key_material",
        "severity_base": "critical",
        "re": re.compile(
            r"(?:privateKey|mnemonic|entropy|secretKey|seedPhrase|hdkey|randomBytes)\s*[:=].{0,120}Math\.random",
            re.I,
        ),
        "title": "Key/mnemonic/entropy assigned from Math.random",
    },
    {
        "id": "getrandomvalues_mock",
        "severity_base": "critical",
        "re": re.compile(
            r"getRandomValues\s*[=:]\s*(?:function|\([^)]*\)\s*=>).{0,200}Math\.random",
            re.I | re.S,
        ),
        "title": "getRandomValues mocked with Math.random",
    },
    {
        "id": "randombytes_math_fallback",
        "severity_base": "critical",
        "re": re.compile(
            r"randombytes|randomBytes|getRandomValues.{0,160}Math\.random|Math\.random.{0,160}(?:randombytes|getRandomValues)",
            re.I | re.S,
        ),
        "title": "CSPRNG fallback to Math.random",
    },
]


def iter_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _severity(base: str, snippet: str) -> str:
    crypto = bool(CRYPTO_HINTS.search(snippet))
    ui = bool(UI_HINTS.search(snippet))
    if base == "critical":
        return "critical"
    if crypto and base in {"high", "medium"}:
        return "critical" if base == "high" else "high"
    if ui and not crypto and base in {"medium", "low"}:
        return "low"
    return base


def scan_unpacked(unpacked: Path, max_findings: int = 80) -> dict:
    findings: list[dict] = []
    files_scanned = 0
    for path in iter_text_files(unpacked):
        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(unpacked))
        for spec in PATTERNS:
            hits = 0
            for match in spec["re"].finditer(text):
                hits += 1
                if hits > MAX_HITS_PER_PATTERN:
                    break
                start = max(0, match.start() - CONTEXT)
                end = min(len(text), match.end() + CONTEXT)
                snippet = re.sub(r"\s+", " ", text[start:end]).strip()
                line_no = text.count("\n", 0, match.start()) + 1
                findings.append(
                    {
                        "pattern": spec["id"],
                        "title": spec["title"],
                        "severity": _severity(spec["severity_base"], snippet),
                        "file": rel,
                        "line": line_no,
                        "snippet": snippet[:400],
                    }
                )
                if len(findings) >= max_findings:
                    return _summarize(findings, files_scanned)
    return _summarize(findings, files_scanned)


def _rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


def _summarize(findings: list[dict], files_scanned: int) -> dict:
    counts: dict[str, int] = {}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    if counts.get("critical"):
        verdict = "vulnerable"
        worst = "critical"
    elif counts.get("high"):
        verdict = "likely_vulnerable"
        worst = "high"
    elif counts.get("medium"):
        verdict = "needs_review"
        worst = "medium"
    elif findings:
        verdict = "low_risk"
        worst = "low"
    else:
        verdict = "no_weak_rng_found"
        worst = "none"
    findings.sort(key=lambda x: (-_rank(x["severity"]), x["file"], x["line"]))
    return {
        "verdict": verdict,
        "worst_severity": worst,
        "files_scanned": files_scanned,
        "finding_count": len(findings),
        "severity_counts": counts,
        "findings": findings,
    }


def main() -> None:
    import sys

    result = scan_unpacked(Path(sys.argv[1]))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
