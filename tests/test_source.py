from __future__ import annotations

import http.client
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from scripts.jyrules.errors import BuildError
from scripts.jyrules.model import SourceSpec
from scripts.jyrules.source import (
    FetchedSource,
    _SafeRedirectHandler,
    fetch_source,
    parse_source_data,
)


def fetched(text: str, locator: str = "https://example.com/rules") -> FetchedSource:
    return FetchedSource(
        data=text.encode("utf-8"),
        locator=locator,
        final_locator=locator,
        content_type="text/plain",
    )


class SourceParsingTests(unittest.TestCase):
    def test_text_domain_source_filters_other_and_unsupported_rules(self) -> None:
        parsed = parse_source_data(
            fetched(
                """
                # comment
                DOMAIN,Exact.Example
                DOMAIN-SUFFIX,suffix.example
                +.native.example
                ! Adblock comment
                example.com^
                192.0.2.1
                IP-CIDR,192.0.2.0/24
                DOMAIN-KEYWORD,tracking
                """
            ),
            "domain",
            "auto",
        )
        self.assertEqual(
            parsed.rules,
            ["exact.example", "+.suffix.example", "+.native.example"],
        )
        self.assertEqual(parsed.detected_format, "text")
        self.assertEqual(parsed.issues["other_behavior:IP-CIDR"], 1)
        self.assertEqual(parsed.issues["other_behavior:ipcidr"], 1)
        self.assertEqual(parsed.issues["invalid_domain"], 1)
        self.assertEqual(parsed.issues["unsupported_rule_type:DOMAIN-KEYWORD"], 1)

    def test_yaml_payload_is_parsed_structurally(self) -> None:
        parsed = parse_source_data(
            fetched(
                """
                payload:
                  - DOMAIN,one.example
                  - "DOMAIN-SUFFIX,two.example"
                  - 42
                """
            ),
            "domain",
            "auto",
        )
        self.assertEqual(parsed.rules, ["one.example", "+.two.example"])
        self.assertEqual(parsed.detected_format, "yaml")
        self.assertEqual(parsed.issues["non_string_rule"], 1)

    def test_auto_yaml_can_have_metadata_before_payload(self) -> None:
        parsed = parse_source_data(
            fetched(
                """
                name: example rules
                payload:
                  - DOMAIN,one.example
                """
            ),
            "domain",
            "auto",
        )
        self.assertEqual(parsed.detected_format, "yaml")
        self.assertEqual(parsed.rules, ["one.example"])

    def test_auto_yaml_accepts_document_directive(self) -> None:
        parsed = parse_source_data(
            fetched("%YAML 1.2\n---\npayload:\n  - two.example\n"),
            "domain",
            "auto",
        )
        self.assertEqual(parsed.detected_format, "yaml")
        self.assertEqual(parsed.rules, ["two.example"])

    def test_yaml_extension_does_not_override_plain_text_content(self) -> None:
        parsed = parse_source_data(
            fetched("one.example\ntwo.example\n", "https://example.com/rules.yaml"),
            "domain",
            "auto",
        )
        self.assertEqual(parsed.detected_format, "text")
        self.assertEqual(parsed.rules, ["one.example", "two.example"])

    def test_explicit_text_and_list_are_never_reinterpreted_as_yaml(self) -> None:
        for declared_format in ("text", "list"):
            with self.subTest(declared_format=declared_format):
                parsed = parse_source_data(
                    fetched("[one.example]\n"),
                    "domain",
                    declared_format,
                )
                self.assertEqual(parsed.detected_format, "text")
                self.assertEqual(parsed.rules, [])
                self.assertEqual(parsed.issues["invalid_domain"], 1)

    def test_ipcidr_source_normalizes_networks(self) -> None:
        parsed = parse_source_data(
            fetched(
                """
                IP-CIDR,192.0.2.7/24,no-resolve
                IP-CIDR6,2001:db8::1/32
                IP-CIDR,198.51.100.0/24,src
                DOMAIN,other.example
                """
            ),
            "ipcidr",
            "text",
        )
        self.assertEqual(parsed.rules, ["192.0.2.0/24", "2001:db8::/32"])
        self.assertEqual(parsed.issues["unsupported_source_ipcidr"], 1)
        self.assertEqual(parsed.issues["other_behavior:DOMAIN"], 1)

    def test_binary_auto_source_uses_mrs_decoder(self) -> None:
        calls: list[tuple[bytes, str]] = []

        def decode(data: bytes, behavior: str) -> str:
            calls.append((data, behavior))
            return "+.decoded.example\n"

        binary = FetchedSource(
            data=b"\x00\xffMRS",
            locator="https://example.com/input.data",
            final_locator="https://example.com/input.data",
            content_type="application/octet-stream",
        )
        parsed = parse_source_data(binary, "domain", "auto", decode)
        self.assertEqual(parsed.detected_format, "mrs")
        self.assertEqual(parsed.rules, ["+.decoded.example"])
        self.assertEqual(calls, [(binary.data, "domain")])

    def test_domain_mrs_can_preserve_numeric_literal(self) -> None:
        binary = FetchedSource(
            data=b"\x00MRS",
            locator="https://example.com/input.mrs",
            final_locator="https://example.com/input.mrs",
            content_type="application/octet-stream",
        )

        parsed = parse_source_data(
            binary,
            "domain",
            "mrs",
            lambda _data, _behavior: "192.0.2.1\n",
        )

        self.assertEqual(parsed.rules, ["192.0.2.1"])
        self.assertEqual(parsed.issues, {})

    def test_yaml_non_string_example_is_bounded(self) -> None:
        shared = ", ".join(str(index) for index in range(200))
        parsed = parse_source_data(
            fetched(f"payload:\n  - &shared [{shared}]\n  - [*shared, *shared]\n"),
            "domain",
            "yaml",
        )

        examples = parsed.examples["non_string_rule"]
        self.assertTrue(examples)
        self.assertTrue(all(len(example) <= 240 for example in examples))

    def test_deep_yaml_recursion_is_wrapped_as_build_error(self) -> None:
        deeply_nested = "[" * 2000 + "x" + "]" * 2000
        with self.assertRaises(BuildError):
            parse_source_data(
                fetched(deeply_nested),
                "domain",
                "yaml",
            )

    def test_html_response_is_rejected(self) -> None:
        with self.assertRaises(BuildError):
            parse_source_data(fetched("<!doctype html><title>404</title>"), "domain", "auto")

    def test_incomplete_http_response_is_wrapped_as_build_error(self) -> None:
        spec = SourceSpec(
            name=None,
            url="https://example.com/rules.txt",
            path=None,
            format="auto",
            optional=True,
        )
        with patch(
            "scripts.jyrules.source._URL_OPENER.open",
            side_effect=http.client.IncompleteRead(b"partial"),
        ):
            with self.assertRaisesRegex(BuildError, "failed to download"):
                fetch_source(spec, Path.cwd())

    def test_redirect_handler_rejects_downgrade_and_private_targets(self) -> None:
        handler = _SafeRedirectHandler()
        request = urllib.request.Request("https://example.com/rules.txt")
        for target in (
            "http://example.com/rules.txt",
            "https://127.0.0.1/rules.txt",
        ):
            with self.subTest(target=target):
                with self.assertRaises(BuildError):
                    handler.redirect_request(
                        request,
                        None,
                        302,
                        "Found",
                        {},
                        target,
                    )


if __name__ == "__main__":
    unittest.main()
