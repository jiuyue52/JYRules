import tempfile
import textwrap
import unittest
from pathlib import Path

from scripts.jyrules.errors import BuildError, TaskConfigError
from scripts.jyrules.model import load_tasks


def task_text(
    *,
    output: str = "CN_Domain",
    behavior: str = "domain",
    extra: str = "",
) -> str:
    return textwrap.dedent(
        f"""
        version = 1
        behavior = "{behavior}"
        output = "{output}"
        {extra}

        [[sources]]
        url = "https://example.com/rules.txt"
        """
    )


class TaskModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tasks = self.root / "tasks"
        self.tasks.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, content: str) -> Path:
        target = self.tasks / name
        target.write_text(textwrap.dedent(content), encoding="utf-8")
        return target

    def test_task_errors_share_the_build_error_base(self) -> None:
        self.assertTrue(issubclass(TaskConfigError, BuildError))

    def test_loads_direct_directory_and_normalizes_aliases(self) -> None:
        self.write(
            "CN_IP.toml",
            r'''
            version = 1
            behavior = "IP"
            output = "CN_IP"

            [[sources]]
            name = "remote mrs"
            url = "https://rules.example.com/cn.mrs"
            format = "MRS"
            optional = true

            [[sources]]
            path = 'sources\cn.list'
            format = "list"

            [[exclude]]
            url = "https://rules.example.com/global.yaml"
            format = "yaml"
            ''',
        )

        tasks = load_tasks(self.tasks)

        self.assertEqual(len(tasks), 1)
        task = tasks[0]
        self.assertEqual(task.name, "CN_IP")
        self.assertEqual(task.definition_path, (self.tasks / "CN_IP.toml").resolve())
        self.assertEqual(task.behavior, "ipcidr")
        self.assertEqual(task.output_directory, "ip")
        self.assertTrue(task.enabled)
        self.assertEqual(task.output, "CN_IP")
        self.assertEqual(len(task.sources), 2)
        self.assertEqual(task.sources[0].name, "remote mrs")
        self.assertEqual(task.sources[0].format, "mrs")
        self.assertTrue(task.sources[0].optional)
        self.assertEqual(task.sources[0].kind, "url")
        self.assertEqual(task.sources[0].locator, "https://rules.example.com/cn.mrs")
        self.assertEqual(task.sources[1].path, "sources/cn.list")
        self.assertEqual(task.sources[1].format, "list")
        self.assertFalse(task.sources[1].optional)
        self.assertEqual(task.exclude[0].kind, "url")

    def test_sorts_tasks_case_insensitively_and_keeps_disabled_tasks(self) -> None:
        self.write("zulu.toml", task_text(output="Zulu"))
        self.write("Alpha.toml", task_text(output="Alpha", extra="enabled = false"))

        tasks = load_tasks(self.tasks)

        self.assertEqual([task.name for task in tasks], ["Alpha", "zulu"])
        self.assertFalse(tasks[0].enabled)

    def test_missing_directory_and_empty_directory_are_empty(self) -> None:
        self.assertEqual(load_tasks(self.root / "missing"), ())
        self.assertEqual(load_tasks(self.tasks), ())

    def test_ignores_non_toml_and_nested_files(self) -> None:
        (self.tasks / "README.md").write_text("ignored", encoding="utf-8")
        nested = self.tasks / "nested"
        nested.mkdir()
        (nested / "nested.toml").write_text(task_text(), encoding="utf-8")
        self.assertEqual(load_tasks(self.tasks), ())

    def test_rejects_unknown_task_and_source_fields(self) -> None:
        for extra, expected in (
            ('policy = "DIRECT"', "policy"),
            ('exclude_policy = "PROXY"', "exclude_policy"),
        ):
            with self.subTest(extra=extra):
                self.write("bad.toml", task_text(extra=extra))
                with self.assertRaisesRegex(TaskConfigError, expected):
                    load_tasks(self.tasks)

        self.write(
            "bad.toml",
            """
            version = 1
            behavior = "domain"
            output = "bad"
            [[sources]]
            url = "https://example.com/rules.txt"
            surprise = true
            """,
        )
        with self.assertRaisesRegex(TaskConfigError, "surprise"):
            load_tasks(self.tasks)

    def test_requires_exactly_one_source_locator(self) -> None:
        cases = (
            "format = \"text\"",
            'url = "https://example.com/rules.txt"\npath = "sources/rules.txt"',
        )
        for source_fields in cases:
            with self.subTest(source_fields=source_fields):
                self.write(
                    "bad.toml",
                    f"""
                    version = 1
                    behavior = "domain"
                    output = "bad"
                    [[sources]]
                    {source_fields}
                    """,
                )
                with self.assertRaisesRegex(TaskConfigError, "exactly one of url or path"):
                    load_tasks(self.tasks)

    def test_rejects_non_public_or_malformed_urls(self) -> None:
        invalid_urls = (
            "http://example.com/rules.txt",
            "https://localhost/rules.txt",
            "https://sub.localhost/rules.txt",
            "https://127.0.0.1/rules.txt",
            "https://10.0.0.1/rules.txt",
            "https://[::1]/rules.txt",
            "https://user:secret@example.com/rules.txt",
            "https://example/rules.txt",
            "https://127.1/rules.txt",
            "https://example.com/rules bad.txt",
        )
        for index, url in enumerate(invalid_urls):
            with self.subTest(url=url):
                self.write(
                    "bad.toml",
                    f'''
                    version = 1
                    behavior = "domain"
                    output = "bad"
                    [[sources]]
                    url = "{url}"
                    ''',
                )
                with self.assertRaises(TaskConfigError):
                    load_tasks(self.tasks)

    def test_accepts_public_ipv4_and_ipv6_urls(self) -> None:
        self.write(
            "one.toml",
            task_text(output="one").replace(
                "https://example.com/rules.txt",
                "https://1.1.1.1/rules.txt",
            ),
        )
        self.write(
            "two.toml",
            task_text(output="two").replace(
                "https://example.com/rules.txt",
                "https://[2606:4700:4700::1111]/rules.txt",
            ),
        )
        self.assertEqual(len(load_tasks(self.tasks)), 2)

    def test_idn_url_is_normalized_for_urllib(self) -> None:
        self.write(
            "idn.toml",
            task_text().replace(
                "https://example.com/rules.txt",
                "https://例子.测试/规则.txt?q=中文",
            ),
        )

        source = load_tasks(self.tasks)[0].sources[0]

        self.assertEqual(
            source.url,
            "https://xn--fsqu00a.xn--0zwm56d/%E8%A7%84%E5%88%99.txt?q=%E4%B8%AD%E6%96%87",
        )

    def test_rejects_unsafe_repository_paths(self) -> None:
        invalid_paths = (
            "../rules.txt",
            "/rules.txt",
            "C:/rules.txt",
            "folder/../../rules.txt",
            "folder//rules.txt",
            "NUL.txt",
            ".git/config",
            "bad?.txt",
            "folder/trailing.",
        )
        for path in invalid_paths:
            with self.subTest(path=path):
                self.write(
                    "bad.toml",
                    f'''
                    version = 1
                    behavior = "domain"
                    output = "bad"
                    [[sources]]
                    path = '{path}'
                    ''',
                )
                with self.assertRaises(TaskConfigError):
                    load_tasks(self.tasks)

    def test_rejects_unsafe_output_stems(self) -> None:
        invalid_outputs = (
            "folder/rules",
            r"folder\rules",
            "NUL",
            "COM1.rules",
            "bad?name",
            "trailing.",
            "rules.mrs",
            "rules.txt",
            ".hidden",
        )
        for output in invalid_outputs:
            with self.subTest(output=output):
                self.write("bad.toml", task_text(output=output))
                with self.assertRaises(TaskConfigError):
                    load_tasks(self.tasks)

    def test_rejects_case_insensitive_generated_output_conflicts(self) -> None:
        self.write("one.toml", task_text(output="Shared"))
        self.write("two.toml", task_text(output="shared"))
        with self.assertRaisesRegex(TaskConfigError, "case-insensitively"):
            load_tasks(self.tasks)

    def test_allows_same_output_in_different_behavior_directories(self) -> None:
        self.write("domain.toml", task_text(output="Shared", behavior="domain"))
        self.write("ip.toml", task_text(output="shared", behavior="ip"))

        tasks = load_tasks(self.tasks)

        self.assertEqual(
            [(task.behavior, task.output_directory, task.output) for task in tasks],
            [
                ("domain", "domain", "Shared"),
                ("ipcidr", "ip", "shared"),
            ],
        )

    def test_ip_alias_and_ipcidr_share_one_output_directory(self) -> None:
        self.write("alias.toml", task_text(output="Shared", behavior="ip"))
        self.write("canonical.toml", task_text(output="shared", behavior="ipcidr"))

        with self.assertRaisesRegex(TaskConfigError, "rules/ip"):
            load_tasks(self.tasks)

    def test_rejects_main_output_that_collides_with_an_exclude_output(self) -> None:
        self.write(
            "one.toml",
            task_text(
                output="Shared",
                extra=textwrap.dedent(
                    '''
                    [[exclude]]
                    url = "https://example.com/exclude.txt"
                    ''',
                ),
            ),
        )
        self.write("two.toml", task_text(output="no_shared"))
        with self.assertRaisesRegex(TaskConfigError, "exclude output"):
            load_tasks(self.tasks)

    def test_rejects_invalid_required_fields_and_source_options(self) -> None:
        invalid_documents = (
            """
            behavior = "domain"
            output = "rules"
            [[sources]]
            url = "https://example.com/rules.txt"
            """,
            """
            version = 2
            behavior = "domain"
            output = "rules"
            [[sources]]
            url = "https://example.com/rules.txt"
            """,
            """
            version = 1
            behavior = "classical"
            output = "rules"
            [[sources]]
            url = "https://example.com/rules.txt"
            """,
            """
            version = 1
            behavior = "domain"
            output = "rules"
            sources = []
            """,
            """
            version = 1
            behavior = "domain"
            output = "rules"
            [[sources]]
            url = "https://example.com/rules.txt"
            format = "binary"
            """,
            """
            version = 1
            behavior = "domain"
            output = "rules"
            [[sources]]
            url = "https://example.com/rules.txt"
            optional = "yes"
            """,
        )
        for index, document in enumerate(invalid_documents):
            with self.subTest(index=index):
                self.write("bad.toml", document)
                with self.assertRaises(TaskConfigError):
                    load_tasks(self.tasks)

    def test_reports_invalid_toml_with_the_definition_path(self) -> None:
        path = self.write("broken.toml", "version = [")
        with self.assertRaises(TaskConfigError) as caught:
            load_tasks(self.tasks)
        self.assertIn(str(path.resolve()), str(caught.exception))
        self.assertIn("cannot read TOML", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
