from __future__ import annotations

import dataclasses
import unittest
from unittest.mock import patch

from scripts.jyrules.setops import (
    SetOperationError,
    collapse_domain_rules,
    collapse_ip_rules,
    compute_domain_setops,
    compute_ip_setops,
    compute_setops,
    deduplication_stats,
    normalize_domain_rule,
    normalize_ip_rule,
)


class DomainNormalizationTests(unittest.TestCase):
    def test_single_rule_normalization(self) -> None:
        self.assertEqual(normalize_domain_rule(" +.Example.COM "), "+.example.com")
        self.assertEqual(normalize_domain_rule(".Example.COM"), ".example.com")
        self.assertEqual(normalize_domain_rule("LOCALHOST"), "localhost")
        self.assertEqual(normalize_domain_rule("测试.CN"), "xn--0zwm56d.cn")

    def test_semantic_merge_and_coverage(self) -> None:
        self.assertEqual(
            collapse_domain_rules(["example.com", ".example.com"]),
            ("+.example.com",),
        )
        self.assertEqual(
            collapse_domain_rules(
                [".example.com", "foo.example.com", "+.bar.example.com"]
            ),
            (".example.com",),
        )
        self.assertEqual(
            collapse_domain_rules(
                ["+.example.com", ".example.com", "foo.example.com"]
            ),
            ("+.example.com",),
        )

    def test_invalid_or_unsupported_domain_rules_fail(self) -> None:
        for rule in (
            "",
            "+.",
            ".",
            "foo..example",
            "*.example.com",
            "foo/bar",
            "---",
            "bad domain.example",
            "example.com:443",
            "bad\\domain.example",
            "example.com^",
            "foo=bar.example",
            "!",
        ):
            with self.subTest(rule=rule):
                with self.assertRaises(SetOperationError):
                    normalize_domain_rule(rule)

    def test_domain_deduplication_stats_separate_reduction_reasons(self) -> None:
        covered = deduplication_stats(
            "domain",
            ["foo.example.com", "foo.example.com", "+.example.com"],
        )
        self.assertEqual(covered.input_rules, 3)
        self.assertEqual(covered.exact_duplicates_removed, 1)
        self.assertEqual(covered.parent_covered_removed, 1)
        self.assertEqual(covered.semantic_merges, 0)
        self.assertEqual(covered.output_rules, 1)

        merged = deduplication_stats(
            "domain",
            ["example.com", ".example.com"],
        )
        self.assertEqual(merged.semantic_merges, 1)
        self.assertEqual(merged.output_rules, 1)


class DomainDifferenceTests(unittest.TestCase):
    def test_exact_base_exclusion_converts_suffix_to_subdomain(self) -> None:
        result = compute_domain_setops(["+.example.com"], ["example.com"])

        self.assertEqual(result.main, (".example.com",))
        self.assertEqual(result.exclude, ("example.com",))
        self.assertEqual(result.removed, ())
        self.assertEqual(result.converted[0].source, "+.example.com")
        self.assertEqual(result.converted[0].replacements, (".example.com",))
        self.assertEqual(result.converted[0].reason, "exclude_exact_base")
        self.assertEqual(result.partial_overlap_retained, ())

    def test_subdomain_exclusion_converts_suffix_to_exact(self) -> None:
        result = compute_domain_setops(["+.example.com"], [".example.com"])

        self.assertEqual(result.main, ("example.com",))
        self.assertEqual(result.converted[0].reason, "exclude_all_subdomains")

    def test_full_coverage_removes_source_atom(self) -> None:
        result = compute_domain_setops(
            ["+.child.example.com"], [".example.com"]
        )

        self.assertEqual(result.main, ())
        self.assertEqual(result.removed, ("+.child.example.com",))

    def test_unrepresentable_child_hole_retains_source_atom(self) -> None:
        result = compute_domain_setops(
            ["+.example.com"], ["ads.example.com"]
        )

        self.assertEqual(result.main, ("+.example.com",))
        self.assertEqual(result.exclude, ("ads.example.com",))
        self.assertEqual(len(result.partial_overlap_retained), 1)
        overlap = result.partial_overlap_retained[0]
        self.assertEqual(overlap.source, "+.example.com")
        self.assertEqual(overlap.exclusions, ("ads.example.com",))
        self.assertEqual(overlap.reason, "partial_overlap_retained")

    def test_mixed_exact_and_partial_exclusion_applies_exact_part_first(self) -> None:
        result = compute_domain_setops(
            ["+.example.com"], ["example.com", "ads.example.com"]
        )

        self.assertEqual(result.main, (".example.com",))
        self.assertEqual(result.converted[0].source, "+.example.com")
        self.assertEqual(result.converted[0].replacements, (".example.com",))
        self.assertEqual(
            result.partial_overlap_retained[0].exclusions,
            ("ads.example.com",),
        )

    def test_dot_rule_does_not_include_its_base(self) -> None:
        result = compute_domain_setops([".example.com"], ["example.com"])

        self.assertEqual(result.main, (".example.com",))
        self.assertEqual(result.partial_overlap_retained, ())

    def test_exclude_output_is_full_independent_set(self) -> None:
        result = compute_domain_setops(
            ["+.example.com"], ["ads.example.com", "unrelated.test"]
        )

        self.assertEqual(
            result.exclude, ("ads.example.com", "unrelated.test")
        )

    def test_partial_overlap_details_are_bounded_but_counted(self) -> None:
        exclusions = [f"host-{index}.example.com" for index in range(150)]

        result = compute_domain_setops(["+.example.com"], exclusions)

        overlap = result.partial_overlap_retained[0]
        self.assertEqual(overlap.exclusion_count, 150)
        self.assertEqual(len(overlap.exclusions), 100)


class IPNormalizationTests(unittest.TestCase):
    def test_single_ip_network_normalization(self) -> None:
        self.assertEqual(normalize_ip_rule("192.0.2.17/24"), "192.0.2.0/24")
        self.assertEqual(normalize_ip_rule("2001:0DB8::1/32"), "2001:db8::/32")
        self.assertEqual(normalize_ip_rule("192.0.2.1"), "192.0.2.1/32")

    def test_collapse_keeps_families_separate(self) -> None:
        self.assertEqual(
            collapse_ip_rules(
                [
                    "10.0.0.0/9",
                    "10.128.0.0/9",
                    "2001:db8::/33",
                    "2001:db8:8000::/33",
                ]
            ),
            ("10.0.0.0/8", "2001:db8::/32"),
        )

    def test_invalid_ip_rule_fails(self) -> None:
        with self.assertRaises(SetOperationError):
            normalize_ip_rule("IP-CIDR,192.0.2.0/24")

    def test_ip_deduplication_stats_count_sibling_merge(self) -> None:
        stats = deduplication_stats(
            "ipcidr",
            ["10.0.0.0/9", "10.0.0.0/9", "10.128.0.0/9"],
        )
        self.assertEqual(stats.exact_duplicates_removed, 1)
        self.assertEqual(stats.parent_covered_removed, 0)
        self.assertEqual(stats.semantic_merges, 1)
        self.assertEqual(stats.output_rules, 1)


class IPDifferenceTests(unittest.TestCase):
    def test_half_network_exclusion(self) -> None:
        result = compute_ip_setops(["10.0.0.0/8"], ["10.0.0.0/9"])

        self.assertEqual(result.main, ("10.128.0.0/9",))
        self.assertEqual(result.exclude, ("10.0.0.0/9",))
        self.assertEqual(result.converted[0].replacements, ("10.128.0.0/9",))
        self.assertEqual(result.converted[0].reason, "ipcidr_difference")
        self.assertEqual(result.partial_overlap_retained, ())

    def test_middle_hole_splits_network_exactly(self) -> None:
        result = compute_ip_setops(["10.0.0.0/8"], ["10.64.0.0/10"])

        self.assertEqual(result.main, ("10.0.0.0/10", "10.128.0.0/9"))

    def test_wider_exclusion_removes_network(self) -> None:
        result = compute_ip_setops(["10.0.0.0/9"], ["10.0.0.0/8"])

        self.assertEqual(result.main, ())
        self.assertEqual(result.removed, ("10.0.0.0/9",))

    def test_ipv4_and_ipv6_are_subtracted_independently(self) -> None:
        result = compute_ip_setops(
            ["10.0.0.0/8", "2001:db8::/32"],
            ["10.0.0.0/9", "2001:db8::/33"],
        )

        self.assertEqual(result.main, ("10.128.0.0/9", "2001:db8:8000::/33"))

    def test_exclude_output_contains_unrelated_networks(self) -> None:
        result = compute_ip_setops(
            ["10.0.0.0/8"], ["192.0.2.0/24", "2001:db8::/32"]
        )

        self.assertEqual(result.main, ("10.0.0.0/8",))
        self.assertEqual(
            result.exclude, ("192.0.2.0/24", "2001:db8::/32")
        )

    def test_large_conversion_details_are_sampled(self) -> None:
        exclusions = [f"{index:x}::/128" for index in range(1, 130)]

        result = compute_ip_setops(["::/0"], exclusions)

        conversion = result.converted[0]
        self.assertGreater(conversion.replacement_count, 100)
        self.assertEqual(len(conversion.replacements), 100)

    def test_ip_difference_has_a_generated_rule_limit(self) -> None:
        exclusions = [f"{index:x}::/128" for index in range(1, 20)]

        with patch("scripts.jyrules.setops.MAX_OUTPUT_RULES", 10):
            with self.assertRaisesRegex(SetOperationError, "generated-rule limit"):
                compute_ip_setops(["::/0"], exclusions)


class PublicInterfaceTests(unittest.TestCase):
    def test_deduplication_stats_scale_to_large_rule_sets(self) -> None:
        domains = [f"host-{index}.example" for index in range(10_000)]
        domain_stats = deduplication_stats("domain", domains)
        self.assertEqual(domain_stats.output_rules, 10_000)

        networks = [f"198.18.{index // 256}.{index % 256}/32" for index in range(10_000)]
        ip_stats = deduplication_stats("ipcidr", networks)
        self.assertEqual(ip_stats.input_rules, 10_000)

    def test_generic_interface_accepts_ip_alias(self) -> None:
        result = compute_setops("ip", ["192.0.2.0/24"], [])

        self.assertEqual(result.behavior, "ipcidr")
        self.assertEqual(result.main, ("192.0.2.0/24",))

    def test_generic_interface_rejects_unknown_behavior(self) -> None:
        with self.assertRaises(SetOperationError):
            compute_setops("classical", [], [])

    def test_result_is_frozen(self) -> None:
        result = compute_setops("domain", ["example.com"], [])

        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.main = ()  # type: ignore[misc]

    def test_string_is_not_accepted_as_rule_iterable(self) -> None:
        with self.assertRaises(SetOperationError):
            compute_domain_setops("example.com", [])


if __name__ == "__main__":
    unittest.main()
