#!/usr/bin/env python3
"""Reproducible throughput benchmark for the GuardEnv scanner.

Generates a synthetic corpus that looks like a real repository - mostly benign
source with a small fraction of planted credentials - then measures wall-clock
throughput for each detector configuration.

Usage::

    python scripts/benchmark.py                 # default: 2,000 files
    python scripts/benchmark.py --files 10000   # larger corpus
    python scripts/benchmark.py --json          # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import shutil
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardenv import Scanner, ScanOptions, __version__

BENIGN_LINES = [
    "import os",
    "from dataclasses import dataclass",
    "logger = logging.getLogger(__name__)",
    "DEFAULT_TIMEOUT_SECONDS = 30",
    'API_BASE_URL = "https://api.internal.acme-corp.io/v2"',
    "def handle_request(request: Request) -> Response:",
    "    return Response(status=200, body=json.dumps(payload))",
    'CACHE_KEY = f"user:{user_id}:profile"',
    "# TODO: move this into the settings module",
    'BUILD_ID = "550e8400-e29b-41d4-a716-446655440000"',
    'RELEASE = "v2.14.7"',
    "MAX_RETRIES = 5",
    'CONTENT_TYPE = "application/x-www-form-urlencoded"',
    "    for item in sorted(items, key=lambda i: i.created_at):",
    "        yield item.serialize()",
]

PLANTED_SECRETS = [
    "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ",
    'GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"',
    "DATABASE_URL=postgresql://svc:Tr0ub4dor3xK@db.internal:5432/billing",
    "STRIPE_SECRET_KEY=sk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp",
    "SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU",
]

#: Fraction of generated files that contain a planted credential.
LEAK_RATE = 0.02


@dataclass(frozen=True)
class Corpus:
    root: Path
    files: int
    lines: int
    bytes: int
    planted: int


def build_corpus(root: Path, files: int, lines_per_file: int, seed: int = 1337) -> Corpus:
    rng = random.Random(seed)
    total_bytes = 0
    total_lines = 0
    planted = 0

    for index in range(files):
        directory = root / f"pkg{index // 100:03d}" / f"mod{index // 10 % 10}"
        directory.mkdir(parents=True, exist_ok=True)
        body = [rng.choice(BENIGN_LINES) for _ in range(lines_per_file)]
        if rng.random() < LEAK_RATE:
            body[rng.randrange(len(body))] = rng.choice(PLANTED_SECRETS)
            planted += 1
        text = "\n".join(body) + "\n"
        path = directory / f"module_{index:05d}.py"
        path.write_text(text, encoding="utf-8")
        total_bytes += len(text.encode("utf-8"))
        total_lines += len(body)

    return Corpus(root=root, files=files, lines=total_lines, bytes=total_bytes, planted=planted)


@dataclass(frozen=True)
class Result:
    label: str
    seconds: float
    files_per_second: float
    mb_per_second: float
    findings: int


def measure(corpus: Corpus, label: str, options: ScanOptions, repeats: int) -> Result:
    scanner = Scanner(options)
    timings: list[float] = []
    findings = 0
    for _ in range(repeats):
        started = time.perf_counter()
        summary = scanner.scan_paths([corpus.root])
        timings.append(time.perf_counter() - started)
        findings = len(summary.findings)

    # Report the best run: it is the measurement least polluted by other load on
    # the machine, and it is the number a reader can most easily reproduce.
    best = min(timings)
    return Result(
        label=label,
        seconds=best,
        files_per_second=corpus.files / best,
        mb_per_second=(corpus.bytes / (1024 * 1024)) / best,
        findings=findings,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=2000, help="number of files to generate")
    parser.add_argument("--lines", type=int, default=120, help="lines per generated file")
    parser.add_argument("--repeats", type=int, default=3, help="timed runs per configuration")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="guardenv-bench-"))
    try:
        corpus = build_corpus(workdir / "corpus", args.files, args.lines)

        configurations = [
            ("regex only", ScanOptions(enable_entropy=False)),
            ("entropy only", ScanOptions(enable_rules=False)),
            ("combined", ScanOptions()),
            ("combined, 4 threads", ScanOptions(workers=4)),
        ]
        results = [measure(corpus, label, options, args.repeats) for label, options in configurations]

        payload = {
            "guardenvVersion": __version__,
            "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.machine()}",
            "corpus": {
                "files": corpus.files,
                "lines": corpus.lines,
                "bytes": corpus.bytes,
                "filesWithPlantedSecrets": corpus.planted,
            },
            "repeats": args.repeats,
            "results": [
                {
                    "configuration": r.label,
                    "seconds": round(r.seconds, 4),
                    "filesPerSecond": round(r.files_per_second),
                    "mbPerSecond": round(r.mb_per_second, 1),
                    "findings": r.findings,
                }
                for r in results
            ],
        }

        if args.json:
            print(json.dumps(payload, indent=2))
            return 0

        print(f"GuardEnv {__version__} · Python {platform.python_version()} · {payload['platform']}")
        print(
            f"Corpus: {corpus.files:,} files · {corpus.lines:,} lines · "
            f"{corpus.bytes / (1024 * 1024):.1f} MB · {corpus.planted} planted secrets"
        )
        print(f"Best of {args.repeats} runs\n")
        print(f"{'configuration':<22}{'seconds':>10}{'files/s':>12}{'MB/s':>10}{'findings':>11}")
        print("-" * 65)
        for result in results:
            print(
                f"{result.label:<22}{result.seconds:>10.3f}{result.files_per_second:>12,.0f}"
                f"{result.mb_per_second:>10.1f}{result.findings:>11,}"
            )

        spread = [r.mb_per_second for r in results]
        print(f"\nMedian throughput across configurations: {statistics.median(spread):.1f} MB/s")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
