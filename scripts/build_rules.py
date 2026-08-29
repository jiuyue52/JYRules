#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from jyrules.builder import build_repository
from jyrules.errors import BuildError


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build merged and semantically deduplicated Mihomo MRS rules."
    )
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--mihomo-version", required=True)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    try:
        report = build_repository(
            tasks_dir=args.tasks,
            output_root=args.output_root,
            repo_root=args.repo_root,
            mihomo=args.mihomo,
            mihomo_version=args.mihomo_version,
        )
    except (BuildError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summary = report["summary"]
    print(
        f"Built {summary['mrs_files']} MRS files from "
        f"{summary['enabled_tasks']} enabled tasks."
    )
    if summary["partial_overlaps_retained"]:
        print(
            f"Warning: retained {summary['partial_overlaps_retained']} "
            "domain rules with non-representable partial exclusions."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

