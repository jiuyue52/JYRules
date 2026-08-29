from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.jyrules.builder import _operation_report, _stable_final_locator, build_repository
from scripts.jyrules.errors import BuildError
from scripts.jyrules.setops import (
    DeduplicationStats,
    PartialOverlap,
    RuleConversion,
    SetOperationResult,
)


class FakeConverter:
    def __init__(self, executable: Path, work_dir: Path) -> None:
        self.executable = executable
        self.work_dir = work_dir

    def decode_mrs(self, data: bytes, behavior: str) -> str:
        return data.decode("utf-8")

    def compile_and_verify(
        self,
        entries: tuple[str, ...],
        behavior: str,
        text_target: Path,
        mrs_target: Path,
    ) -> None:
        text_target.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(f"{entry}\n" for entry in entries)
        text_target.write_text(content, encoding="utf-8", newline="\n")
        mrs_target.write_bytes(b"fake-mrs\n" + content.encode("utf-8"))


class BuilderTests(unittest.TestCase):
    def test_operation_report_bounds_nested_examples(self) -> None:
        many = tuple(f"item-{index}" for index in range(150))
        result = SetOperationResult(
            behavior="domain",
            source=("+.example.com",),
            main=("+.example.com",),
            exclude=many,
            removed=(),
            converted=(RuleConversion("source", many, "test"),),
            partial_overlap_retained=(PartialOverlap("source", many),),
        )
        stats = DeduplicationStats(1, 0, 0, 0, 1)

        report = _operation_report(result, stats, stats)

        converted = report["converted"][0]
        partial = report["partial_overlap_retained"][0]
        self.assertEqual(len(converted["replacements"]), 100)
        self.assertEqual(converted["replacement_count"], 150)
        self.assertTrue(converted["replacements_truncated"])
        self.assertEqual(len(partial["exclusions"]), 100)
        self.assertEqual(partial["exclusion_count"], 150)
        self.assertTrue(partial["exclusions_truncated"])

    def test_final_redirect_query_is_not_written_to_report(self) -> None:
        self.assertEqual(
            _stable_final_locator(
                "https://release-assets.example/rules.mrs?token=short-lived#part",
                "url",
            ),
            "https://release-assets.example/rules.mrs",
        )
        self.assertEqual(_stable_final_locator("local/rules.list", "path"), "local/rules.list")

    def test_builds_main_and_complete_no_ruleset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            tasks = repo / "tasks"
            local = repo / "local"
            stage = root / "stage"
            tasks.mkdir(parents=True)
            local.mkdir()
            (local / "source.list").write_text(
                "+.example.com\nremove.test\n", encoding="utf-8"
            )
            (local / "exclude.list").write_text(
                "ads.example.com\nremove.test\nunrelated.example\n", encoding="utf-8"
            )
            (tasks / "CN_Domain.toml").write_text(
                """
                version = 1
                behavior = "domain"
                output = "CN_Domain"

                [[sources]]
                path = "local/source.list"

                [[exclude]]
                path = "local/exclude.list"
                """,
                encoding="utf-8",
            )

            with patch("scripts.jyrules.builder.MihomoConverter", FakeConverter):
                report = build_repository(
                    tasks,
                    stage,
                    repo,
                    root / "mihomo",
                    "test-version",
                )

            self.assertEqual(
                (stage / "rules/domain/CN_Domain.txt")
                .read_text(encoding="utf-8")
                .splitlines(),
                ["+.example.com"],
            )
            self.assertEqual(
                (stage / "rules/domain/NO_CN_Domain.txt")
                .read_text(encoding="utf-8")
                .splitlines(),
                ["ads.example.com", "remove.test", "unrelated.example"],
            )
            self.assertFalse((stage / "rules/ip").exists())
            self.assertEqual(
                [output["path"] for output in report["tasks"][0]["outputs"]],
                [
                    "rules/domain/CN_Domain.mrs",
                    "rules/domain/CN_Domain.txt",
                    "rules/domain/NO_CN_Domain.mrs",
                    "rules/domain/NO_CN_Domain.txt",
                ],
            )
            operation = report["tasks"][0]["set_operations"]
            self.assertEqual(operation["removed_source_rules"], 1)
            self.assertEqual(operation["partial_overlaps_retained"], 1)
            committed_report = json.loads(
                (stage / "reports/conversion-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(committed_report, report)

    def test_optional_missing_source_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            tasks = repo / "tasks"
            local = repo / "local"
            stage = root / "stage"
            tasks.mkdir(parents=True)
            local.mkdir()
            (local / "source.list").write_text("one.example\n", encoding="utf-8")
            (local / "invalid.list").write_text("example.com^\n", encoding="utf-8")
            (tasks / "one.toml").write_text(
                """
                version = 1
                behavior = "domain"
                output = "One"

                [[sources]]
                path = "local/missing.list"
                optional = true

                [[sources]]
                path = "local/source.list"

                [[sources]]
                path = "local/invalid.list"
                optional = true
                """,
                encoding="utf-8",
            )

            with patch("scripts.jyrules.builder.MihomoConverter", FakeConverter):
                report = build_repository(
                    tasks, stage, repo, root / "mihomo", "test-version"
                )
            sources = report["tasks"][0]["sources"]
            self.assertEqual(
                [item["status"] for item in sources],
                ["skipped", "ok", "skipped"],
            )
            self.assertEqual(
                sources[2]["rejected"]["invalid_domain"]["count"],
                1,
            )
            self.assertTrue((stage / "rules/domain/One.mrs").is_file())
            self.assertFalse((stage / "rules/domain/NO_One.mrs").exists())

    def test_same_stem_is_separated_by_behavior_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            tasks = repo / "tasks"
            local = repo / "local"
            stage = root / "stage"
            tasks.mkdir(parents=True)
            local.mkdir()
            (local / "domain.list").write_text("one.example\n", encoding="utf-8")
            (local / "domain-exclude.list").write_text(
                "blocked.example\n", encoding="utf-8"
            )
            (local / "ip.list").write_text("192.0.2.0/24\n", encoding="utf-8")
            (local / "ip-exclude.list").write_text(
                "198.51.100.0/24\n", encoding="utf-8"
            )
            (tasks / "domain.toml").write_text(
                """
                version = 1
                behavior = "domain"
                output = "Shared"
                [[sources]]
                path = "local/domain.list"
                [[exclude]]
                path = "local/domain-exclude.list"
                """,
                encoding="utf-8",
            )
            (tasks / "ip.toml").write_text(
                """
                version = 1
                behavior = "ip"
                output = "Shared"
                [[sources]]
                path = "local/ip.list"
                [[exclude]]
                path = "local/ip-exclude.list"
                """,
                encoding="utf-8",
            )

            with patch("scripts.jyrules.builder.MihomoConverter", FakeConverter):
                report = build_repository(
                    tasks, stage, repo, root / "mihomo", "test-version"
                )

            self.assertTrue((stage / "rules/domain/Shared.mrs").is_file())
            self.assertTrue((stage / "rules/domain/NO_Shared.mrs").is_file())
            self.assertTrue((stage / "rules/ip/Shared.mrs").is_file())
            self.assertTrue((stage / "rules/ip/NO_Shared.mrs").is_file())
            self.assertFalse((stage / "rules/Shared.mrs").exists())
            self.assertFalse((stage / "rules/NO_Shared.mrs").exists())
            self.assertEqual(
                [task["behavior"] for task in report["tasks"]],
                ["domain", "ipcidr"],
            )
            self.assertEqual(
                [task["output_directory"] for task in report["tasks"]],
                ["rules/domain", "rules/ip"],
            )
            output_paths = [
                output["path"]
                for task in report["tasks"]
                for output in task["outputs"]
            ]
            self.assertEqual(
                output_paths,
                [
                    "rules/domain/Shared.mrs",
                    "rules/domain/Shared.txt",
                    "rules/domain/NO_Shared.mrs",
                    "rules/domain/NO_Shared.txt",
                    "rules/ip/Shared.mrs",
                    "rules/ip/Shared.txt",
                    "rules/ip/NO_Shared.mrs",
                    "rules/ip/NO_Shared.txt",
                ],
            )
            self.assertEqual(report["schema_version"], 2)

    def test_rebuild_removes_flat_and_inactive_category_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            tasks = repo / "tasks"
            local = repo / "local"
            stage = root / "stage"
            tasks.mkdir(parents=True)
            local.mkdir()
            (local / "domain.list").write_text("one.example\n", encoding="utf-8")
            (local / "ip.list").write_text("192.0.2.0/24\n", encoding="utf-8")
            task_path = tasks / "switch.toml"
            task_path.write_text(
                """
                version = 1
                behavior = "domain"
                output = "Switch"
                [[sources]]
                path = "local/domain.list"
                """,
                encoding="utf-8",
            )

            with patch("scripts.jyrules.builder.MihomoConverter", FakeConverter):
                build_repository(tasks, stage, repo, root / "mihomo", "v1")
                (stage / "rules/Legacy.mrs").write_bytes(b"old")
                task_path.write_text(
                    """
                    version = 1
                    behavior = "ipcidr"
                    output = "Switch"
                    [[sources]]
                    path = "local/ip.list"
                    """,
                    encoding="utf-8",
                )
                build_repository(tasks, stage, repo, root / "mihomo", "v2")

            self.assertFalse((stage / "rules/Legacy.mrs").exists())
            self.assertFalse((stage / "rules/domain").exists())
            self.assertTrue((stage / "rules/ip/Switch.mrs").is_file())

    def test_refuses_unmarked_existing_output_without_deleting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            output = root / "existing"
            sentinel = output / "rules" / "keep.txt"
            repo.mkdir()
            sentinel.parent.mkdir(parents=True)
            sentinel.write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(BuildError, "not owned by JYRules"):
                build_repository(
                    repo / "tasks",
                    output,
                    repo,
                    root / "mihomo",
                    "test-version",
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_refuses_output_inside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()

            with self.assertRaisesRegex(BuildError, "outside the repository tree"):
                build_repository(
                    repo / "tasks",
                    repo / "stage",
                    repo,
                    repo / "mihomo",
                    "test-version",
                )

    def test_zero_tasks_produces_empty_rules_and_a_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            tasks = repo / "tasks"
            output = root / "stage"
            tasks.mkdir(parents=True)

            report = build_repository(
                tasks,
                output,
                repo,
                root / "mihomo",
                "test-version",
            )

            self.assertEqual(report["summary"]["enabled_tasks"], 0)
            self.assertEqual(list((output / "rules").iterdir()), [])
            self.assertTrue((output / "reports/conversion-report.json").is_file())


if __name__ == "__main__":
    unittest.main()
