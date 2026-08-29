from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from scripts.jyrules.builder import build_repository
from scripts.jyrules.mihomo import MihomoConverter


MIHOMO_BIN = os.environ.get("MIHOMO_BIN")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(MIHOMO_BIN, "MIHOMO_BIN is not set")
class MihomoIntegrationTests(unittest.TestCase):
    def test_real_mrs_input_build_and_deterministic_round_trip(self) -> None:
        assert MIHOMO_BIN is not None
        mihomo = Path(MIHOMO_BIN)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            tasks = repo / "tasks"
            local = repo / "local"
            tasks.mkdir(parents=True)
            local.mkdir()

            seed_converter = MihomoConverter(mihomo, root / "seed-work")
            seed_converter.compile_and_verify(
                (".mrs-subonly.test", "mrs-only.test"),
                "domain",
                local / "mrs-source.txt",
                local / "mrs-source.mrs",
            )
            (local / "source.list").write_text(
                "+.example.com\nremove.test\n", encoding="utf-8"
            )
            (local / "source.yaml").write_text(
                "payload:\n"
                "  - DOMAIN,exact.other\n"
                "  - DOMAIN-SUFFIX,example.com\n",
                encoding="utf-8",
            )
            (local / "exclude.list").write_text(
                "example.com\nads.example.com\nremove.test\nunrelated.test\n",
                encoding="utf-8",
            )
            (tasks / "CN_Domain.toml").write_text(
                """
                version = 1
                behavior = "domain"
                output = "CN_Domain"

                [[sources]]
                path = "local/source.list"
                format = "auto"

                [[sources]]
                path = "local/source.yaml"
                format = "auto"

                [[sources]]
                path = "local/mrs-source.mrs"
                format = "auto"

                [[exclude]]
                path = "local/exclude.list"
                format = "list"
                """,
                encoding="utf-8",
            )

            reports = []
            stages = []
            for number in (1, 2):
                stage = root / f"stage-{number}"
                stages.append(stage)
                reports.append(
                    build_repository(
                        tasks,
                        stage,
                        repo,
                        mihomo,
                        "v1.19.30",
                    )
                )

            main_text = (stages[0] / "rules/domain/CN_Domain.txt").read_text(
                encoding="utf-8"
            )
            no_text = (stages[0] / "rules/domain/NO_CN_Domain.txt").read_text(
                encoding="utf-8"
            )
            self.assertEqual(
                main_text.splitlines(),
                [
                    ".example.com",
                    ".mrs-subonly.test",
                    "exact.other",
                    "mrs-only.test",
                ],
            )
            self.assertEqual(
                no_text.splitlines(),
                [
                    "ads.example.com",
                    "example.com",
                    "remove.test",
                    "unrelated.test",
                ],
            )
            self.assertEqual(
                reports[0]["summary"]["partial_overlaps_retained"], 1
            )

            for relative in (
                "rules/domain/CN_Domain.mrs",
                "rules/domain/CN_Domain.txt",
                "rules/domain/NO_CN_Domain.mrs",
                "rules/domain/NO_CN_Domain.txt",
                "reports/conversion-report.json",
            ):
                self.assertEqual(
                    sha256(stages[0] / relative),
                    sha256(stages[1] / relative),
                    relative,
                )

    def test_real_ip_mrs_input_uses_ip_directory(self) -> None:
        assert MIHOMO_BIN is not None
        mihomo = Path(MIHOMO_BIN)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            tasks = repo / "tasks"
            local = repo / "local"
            stage = root / "stage"
            tasks.mkdir(parents=True)
            local.mkdir()

            seed_converter = MihomoConverter(mihomo, root / "seed-work")
            seed_converter.compile_and_verify(
                ("192.0.2.0/24",),
                "ipcidr",
                local / "source.txt",
                local / "source.mrs",
            )
            (local / "exclude.list").write_text(
                "192.0.2.128/25\n198.51.100.0/24\n",
                encoding="utf-8",
            )
            (tasks / "CN_IP.toml").write_text(
                """
                version = 1
                behavior = "ip"
                output = "Shared"

                [[sources]]
                path = "local/source.mrs"
                format = "mrs"

                [[exclude]]
                path = "local/exclude.list"
                format = "list"
                """,
                encoding="utf-8",
            )

            report = build_repository(
                tasks,
                stage,
                repo,
                mihomo,
                "v1.19.30",
            )

            self.assertEqual(
                (stage / "rules/ip/Shared.txt")
                .read_text(encoding="utf-8")
                .splitlines(),
                ["192.0.2.0/25"],
            )
            self.assertEqual(
                (stage / "rules/ip/NO_Shared.txt")
                .read_text(encoding="utf-8")
                .splitlines(),
                ["192.0.2.128/25", "198.51.100.0/24"],
            )
            self.assertFalse((stage / "rules/domain").exists())
            self.assertFalse((stage / "rules/Shared.mrs").exists())
            self.assertEqual(report["schema_version"], 2)
            task_report = report["tasks"][0]
            self.assertEqual(task_report["behavior"], "ipcidr")
            self.assertEqual(task_report["output_directory"], "rules/ip")
            self.assertEqual(
                [output["path"] for output in task_report["outputs"]],
                [
                    "rules/ip/Shared.mrs",
                    "rules/ip/Shared.txt",
                    "rules/ip/NO_Shared.mrs",
                    "rules/ip/NO_Shared.txt",
                ],
            )


if __name__ == "__main__":
    unittest.main()
