from __future__ import annotations

import hashlib
import json
import shutil
import urllib.parse
from pathlib import Path

from .errors import BuildError
from .mihomo import MihomoConverter
from .model import OutputDirectory, SourceSpec, Task, load_tasks
from .setops import (
    DeduplicationStats,
    SetOperationResult,
    compute_setops,
    deduplication_stats,
)
from .source import ParsedSource, fetch_source, parse_source_data


MAX_OPERATION_EXAMPLES = 100
STAGING_MARKER = ".jyrules-build-root"
STAGING_MARKER_CONTENT = "JYRules staging directory v1\n"


def _source_name(spec: SourceSpec) -> str:
    return spec.name or spec.locator


def _source_report_base(spec: SourceSpec) -> dict[str, object]:
    return {
        "name": _source_name(spec),
        "kind": spec.kind,
        "source": spec.locator,
        "declared_format": spec.format,
        "optional": spec.optional,
    }


def _stable_final_locator(locator: str, kind: str) -> str:
    if kind != "url":
        return locator
    parsed = urllib.parse.urlsplit(locator)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "", "")
    )


def _parsed_source_report(parsed: ParsedSource) -> dict[str, object]:
    return {
        "detected_format": parsed.detected_format,
        "candidate_rules": parsed.candidates,
        "accepted_rules_before_deduplication": len(parsed.rules),
        "rejected_rules": sum(parsed.issues.values()),
        "rejected": parsed.issues_json(),
    }


def _parse_one_source(
    spec: SourceSpec,
    task: Task,
    repo_root: Path,
    converter: MihomoConverter,
) -> tuple[tuple[str, ...], dict[str, object]]:
    report = _source_report_base(spec)
    fetched = None
    parsed = None
    try:
        fetched = fetch_source(spec, repo_root)
        parsed = parse_source_data(
            fetched,
            task.behavior,
            spec.format,
            converter.decode_mrs,
        )
        if not parsed.rules:
            raise BuildError(
                f"source produced no valid {task.behavior} rules: {spec.locator}"
            )
    except BuildError as exc:
        if not spec.optional:
            raise BuildError(f"task {task.name}: {exc}") from exc
        if fetched is not None:
            report["final_source"] = _stable_final_locator(
                fetched.final_locator,
                spec.kind,
            )
        if parsed is not None:
            report.update(_parsed_source_report(parsed))
        report.update({"status": "skipped", "error": str(exc)})
        return (), report

    report.update(
        {
            "status": "ok",
            "final_source": _stable_final_locator(fetched.final_locator, spec.kind),
            **_parsed_source_report(parsed),
        }
    )
    return tuple(parsed.rules), report


def _parse_source_group(
    specs: tuple[SourceSpec, ...],
    task: Task,
    repo_root: Path,
    converter: MihomoConverter,
) -> tuple[tuple[str, ...], list[dict[str, object]]]:
    entries: list[str] = []
    reports: list[dict[str, object]] = []
    for spec in specs:
        parsed, report = _parse_one_source(spec, task, repo_root, converter)
        entries.extend(parsed)
        reports.append(report)
    return tuple(entries), reports


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_ruleset(
    converter: MihomoConverter,
    rules_dir: Path,
    output_directory: OutputDirectory,
    stem: str,
    behavior: str,
    entries: tuple[str, ...],
) -> list[dict[str, object]]:
    output_dir = rules_dir / output_directory
    text_path = output_dir / f"{stem}.txt"
    mrs_path = output_dir / f"{stem}.mrs"
    converter.compile_and_verify(entries, behavior, text_path, mrs_path)
    return [
        {
            "path": f"rules/{output_directory}/{mrs_path.name}",
            "format": "mrs",
            "behavior": behavior,
            "rules": len(entries),
            "sha256": _sha256(mrs_path),
        },
        {
            "path": f"rules/{output_directory}/{text_path.name}",
            "format": "text",
            "behavior": behavior,
            "rules": len(entries),
            "sha256": _sha256(text_path),
        },
    ]


def _deduplication_report(stats: DeduplicationStats) -> dict[str, int]:
    return {
        "input_rules": stats.input_rules,
        "exact_duplicates_removed": stats.exact_duplicates_removed,
        "parent_covered_removed": stats.parent_covered_removed,
        "semantic_merges": stats.semantic_merges,
        "output_rules": stats.output_rules,
    }


def _operation_report(
    result: SetOperationResult,
    source_deduplication: DeduplicationStats,
    exclude_deduplication: DeduplicationStats,
) -> dict[str, object]:
    partial = result.partial_overlap_retained
    converted = result.converted
    return {
        "source_rules_after_semantic_deduplication": len(result.source),
        "exclude_rules_after_semantic_deduplication": len(result.exclude),
        "main_rules": len(result.main),
        "removed_source_rules": len(result.removed),
        "converted_source_rules": len(converted),
        "partial_overlaps_retained": len(partial),
        "source_deduplication": _deduplication_report(source_deduplication),
        "exclude_deduplication": _deduplication_report(exclude_deduplication),
        "removed": list(result.removed[:MAX_OPERATION_EXAMPLES]),
        "converted": [
            {
                "source": item.source,
                "replacements": list(item.replacements[:MAX_OPERATION_EXAMPLES]),
                "replacement_count": item.replacement_count,
                "replacements_truncated": item.replacement_count
                > min(len(item.replacements), MAX_OPERATION_EXAMPLES),
                "reason": item.reason,
            }
            for item in converted[:MAX_OPERATION_EXAMPLES]
        ],
        "partial_overlap_retained": [
            {
                "source": item.source,
                "exclusions": list(item.exclusions[:MAX_OPERATION_EXAMPLES]),
                "exclusion_count": item.exclusion_count,
                "exclusions_truncated": item.exclusion_count
                > min(len(item.exclusions), MAX_OPERATION_EXAMPLES),
                "reason": item.reason,
            }
            for item in partial[:MAX_OPERATION_EXAMPLES]
        ],
        "examples_truncated": (
            len(result.removed) > MAX_OPERATION_EXAMPLES
            or len(converted) > MAX_OPERATION_EXAMPLES
            or len(partial) > MAX_OPERATION_EXAMPLES
            or any(
                item.replacement_count
                > min(len(item.replacements), MAX_OPERATION_EXAMPLES)
                for item in converted
            )
            or any(
                item.exclusion_count
                > min(len(item.exclusions), MAX_OPERATION_EXAMPLES)
                for item in partial
            )
        ),
    }


def _build_task(
    task: Task,
    repo_root: Path,
    rules_dir: Path,
    converter: MihomoConverter,
) -> dict[str, object]:
    source_entries, source_reports = _parse_source_group(
        task.sources, task, repo_root, converter
    )
    if not source_entries:
        raise BuildError(f"task {task.name}: every source was skipped")

    exclude_entries, exclude_reports = _parse_source_group(
        task.exclude, task, repo_root, converter
    )
    result = compute_setops(task.behavior, source_entries, exclude_entries)
    source_deduplication = deduplication_stats(task.behavior, source_entries)
    exclude_deduplication = deduplication_stats(task.behavior, exclude_entries)
    if not result.main:
        raise BuildError(
            f"task {task.name}: exclusions removed the complete source set"
        )

    outputs = _write_ruleset(
        converter,
        rules_dir,
        task.output_directory,
        task.output,
        task.behavior,
        result.main,
    )
    if result.exclude:
        outputs.extend(
            _write_ruleset(
                converter,
                rules_dir,
                task.output_directory,
                f"NO_{task.output}",
                task.behavior,
                result.exclude,
            )
        )

    return {
        "task": task.name,
        "definition": task.definition_path.name,
        "behavior": task.behavior,
        "output_directory": f"rules/{task.output_directory}",
        "output": task.output,
        "sources": source_reports,
        "exclude": exclude_reports,
        "set_operations": _operation_report(
            result,
            source_deduplication,
            exclude_deduplication,
        ),
        "outputs": outputs,
    }


def _validate_derived_outputs(tasks: tuple[Task, ...]) -> None:
    claims: dict[tuple[str, str], tuple[str, str]] = {}
    for task in tasks:
        stems = [(task.output, "main")]
        if task.exclude:
            stems.append((f"NO_{task.output}", "exclude"))
        for stem, kind in stems:
            key = (task.output_directory, stem.casefold())
            if key in claims:
                other_task, other_kind = claims[key]
                raise BuildError(
                    f"task {task.name} {kind} output {stem!r} in "
                    f"rules/{task.output_directory} conflicts with "
                    f"task {other_task} {other_kind} output"
                )
            claims[key] = (task.name, kind)


def _prepare_output_root(output_root: Path, repo_root: Path) -> None:
    if output_root.parent == output_root:
        raise BuildError("output root must not be a filesystem root")
    if (
        output_root == repo_root
        or output_root in repo_root.parents
        or repo_root in output_root.parents
    ):
        raise BuildError("output root must be outside the repository tree")

    marker = output_root / STAGING_MARKER
    if output_root.exists():
        if not output_root.is_dir():
            raise BuildError("output root exists but is not a directory")
        try:
            marker_content = marker.read_text(encoding="ascii")
        except OSError as exc:
            raise BuildError(
                "existing output root is not owned by JYRules; choose a new staging directory"
            ) from exc
        if marker_content != STAGING_MARKER_CONTENT:
            raise BuildError(
                "existing output root has an invalid JYRules staging marker"
            )
        return

    output_root.mkdir(parents=True)
    marker.write_text(STAGING_MARKER_CONTENT, encoding="ascii", newline="\n")


def build_repository(
    tasks_dir: Path,
    output_root: Path,
    repo_root: Path,
    mihomo: Path,
    mihomo_version: str,
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    output_root = output_root.resolve()
    _prepare_output_root(output_root, repo_root)

    tasks = load_tasks(tasks_dir)
    _validate_derived_outputs(tasks)
    enabled = tuple(task for task in tasks if task.enabled)

    rules_dir = output_root / "rules"
    reports_dir = output_root / "reports"
    work_dir = output_root / ".work"
    for path in (rules_dir, reports_dir, work_dir):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)

    task_reports: list[dict[str, object]] = []
    if enabled:
        converter = MihomoConverter(mihomo, work_dir)
        for task in enabled:
            task_reports.append(_build_task(task, repo_root, rules_dir, converter))

    output_files = sum(len(task["outputs"]) for task in task_reports)
    report = {
        "schema_version": 2,
        "mihomo_version": mihomo_version,
        "summary": {
            "task_definitions": len(tasks),
            "enabled_tasks": len(enabled),
            "disabled_tasks": len(tasks) - len(enabled),
            "generated_files": output_files,
            "mrs_files": output_files // 2,
            "partial_overlaps_retained": sum(
                int(task["set_operations"]["partial_overlaps_retained"])
                for task in task_reports
            ),
        },
        "disabled": [task.name for task in tasks if not task.enabled],
        "tasks": task_reports,
    }
    report_path = reports_dir / "conversion-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    shutil.rmtree(work_dir)
    return report
