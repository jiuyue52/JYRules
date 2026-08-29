from __future__ import annotations

import ipaddress
from bisect import insort
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Sequence


class SetOperationError(ValueError):
    pass


MAX_OUTPUT_RULES = 1_000_000
MAX_SETOP_DETAILS = 100


class DomainKind(str, Enum):
    EXACT = "exact"
    SUFFIX = "suffix"
    SUBDOMAIN = "subdomain"


@dataclass(frozen=True)
class RuleConversion:
    source: str
    replacements: tuple[str, ...]
    reason: str
    replacement_count: int = -1

    def __post_init__(self) -> None:
        if self.replacement_count == -1:
            object.__setattr__(self, "replacement_count", len(self.replacements))
        elif self.replacement_count < len(self.replacements):
            raise ValueError("replacement_count must include every stored replacement")


@dataclass(frozen=True)
class PartialOverlap:
    source: str
    exclusions: tuple[str, ...]
    reason: str = "partial_overlap_retained"
    exclusion_count: int = -1

    def __post_init__(self) -> None:
        if self.exclusion_count == -1:
            object.__setattr__(self, "exclusion_count", len(self.exclusions))
        elif self.exclusion_count < len(self.exclusions):
            raise ValueError("exclusion_count must include every stored exclusion")


@dataclass(frozen=True)
class DeduplicationStats:
    input_rules: int
    exact_duplicates_removed: int
    parent_covered_removed: int
    semantic_merges: int
    output_rules: int


@dataclass(frozen=True)
class SetOperationResult:
    behavior: str
    source: tuple[str, ...]
    main: tuple[str, ...]
    exclude: tuple[str, ...]
    removed: tuple[str, ...]
    converted: tuple[RuleConversion, ...]
    partial_overlap_retained: tuple[PartialOverlap, ...]


@dataclass(frozen=True)
class _DomainAtom:
    kind: DomainKind
    base: str

    def render(self) -> str:
        if self.kind is DomainKind.SUFFIX:
            return f"+.{self.base}"
        if self.kind is DomainKind.SUBDOMAIN:
            return f".{self.base}"
        return self.base


class _DomainIndexNode:
    __slots__ = ("atoms", "children")

    def __init__(self) -> None:
        self.atoms: set[_DomainAtom] = set()
        self.children: dict[str, _DomainIndexNode] = {}


class _DomainIndex:
    def __init__(self, atoms: Iterable[_DomainAtom]) -> None:
        self.root = _DomainIndexNode()
        for atom in atoms:
            node = self.root
            for label in reversed(atom.base.split(".")):
                node = node.children.setdefault(label, _DomainIndexNode())
            node.atoms.add(atom)

    def iter_overlapping(self, atom: _DomainAtom) -> Iterable[_DomainAtom]:
        node = self.root
        for label in reversed(atom.base.split(".")):
            node = node.children.get(label)
            if node is None:
                return
            for candidate in node.atoms:
                if _domain_intersection(atom, candidate) is not None:
                    yield candidate

        if atom.kind is not DomainKind.EXACT:
            stack = list(node.children.values())
            while stack:
                current = stack.pop()
                for candidate in current.atoms:
                    if _domain_intersection(atom, candidate) is not None:
                        yield candidate
                stack.extend(current.children.values())


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _domain_atom_sort_key(atom: _DomainAtom) -> str:
    return atom.render()


def _rule_values(values: Iterable[str], label: str) -> Iterable[str]:
    if isinstance(values, (str, bytes)):
        raise SetOperationError(f"{label} must be an iterable of rule strings")
    return values


def _parse_domain_rule(value: str) -> _DomainAtom:
    if not isinstance(value, str):
        raise SetOperationError("domain rule must be a string")

    rule = value.strip().lower()
    if not rule:
        raise SetOperationError("domain rule must not be empty")

    if rule.startswith("+."):
        kind = DomainKind.SUFFIX
        base = rule[2:]
    elif rule.startswith("."):
        kind = DomainKind.SUBDOMAIN
        base = rule[1:]
    else:
        kind = DomainKind.EXACT
        base = rule

    if not base or base.endswith("."):
        raise SetOperationError(f"invalid domain rule: {value!r}")
    labels = base.split(".")
    ascii_labels: list[str] = []
    for label in labels:
        try:
            ascii_label = label.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise SetOperationError(f"invalid domain rule: {value!r}") from exc
        if (
            not ascii_label
            or len(ascii_label) > 63
            or ascii_label.startswith("-")
            or ascii_label.endswith("-")
            or any(
                not (character.isalnum() or character in "-_")
                for character in ascii_label
            )
        ):
            raise SetOperationError(f"invalid domain rule: {value!r}")
        ascii_labels.append(ascii_label)
    if len(".".join(ascii_labels)) > 253:
        raise SetOperationError(f"invalid domain rule: {value!r}")

    return _DomainAtom(kind, ".".join(ascii_labels).lower())


def normalize_domain_rule(value: str) -> str:
    """Return one canonical exact, +.suffix, or .subdomain rule."""

    return _parse_domain_rule(value).render()


def _strict_ancestor_bases(base: str) -> Iterable[str]:
    labels = base.split(".")
    for index in range(1, len(labels)):
        yield ".".join(labels[index:])


def _minimize_domain_atoms(atoms: Iterable[_DomainAtom]) -> tuple[_DomainAtom, ...]:
    unique = set(atoms)
    exact = {atom.base for atom in unique if atom.kind is DomainKind.EXACT}
    suffix = {atom.base for atom in unique if atom.kind is DomainKind.SUFFIX}
    subdomain = {atom.base for atom in unique if atom.kind is DomainKind.SUBDOMAIN}

    combined = exact & subdomain
    exact -= combined
    subdomain -= combined
    suffix |= combined

    kept_suffix: set[str] = set()
    for base in suffix:
        if any(
            ancestor in suffix or ancestor in subdomain
            for ancestor in _strict_ancestor_bases(base)
        ):
            continue
        kept_suffix.add(base)

    kept_subdomain: set[str] = set()
    for base in subdomain:
        if base in suffix:
            continue
        if any(
            ancestor in suffix or ancestor in subdomain
            for ancestor in _strict_ancestor_bases(base)
        ):
            continue
        kept_subdomain.add(base)

    kept_exact: set[str] = set()
    for base in exact:
        if base in suffix:
            continue
        if any(
            ancestor in suffix or ancestor in subdomain
            for ancestor in _strict_ancestor_bases(base)
        ):
            continue
        kept_exact.add(base)

    minimized = {
        *(_DomainAtom(DomainKind.SUFFIX, base) for base in kept_suffix),
        *(_DomainAtom(DomainKind.SUBDOMAIN, base) for base in kept_subdomain),
        *(_DomainAtom(DomainKind.EXACT, base) for base in kept_exact),
    }
    return tuple(sorted(minimized, key=_domain_atom_sort_key))


def _normalize_domain_atoms(values: Iterable[str], label: str) -> tuple[_DomainAtom, ...]:
    return _minimize_domain_atoms(
        _parse_domain_rule(value) for value in _rule_values(values, label)
    )


def collapse_domain_rules(values: Iterable[str]) -> tuple[str, ...]:
    """Canonicalize and semantically minimize domain rules."""

    return tuple(
        atom.render() for atom in _normalize_domain_atoms(values, "domain rules")
    )


def _domain_deduplication_stats(values: Iterable[str]) -> DeduplicationStats:
    parsed = tuple(
        _parse_domain_rule(value) for value in _rule_values(values, "domain rules")
    )
    unique = set(parsed)
    minimized = _minimize_domain_atoms(unique)
    suffix_bases = {
        atom.base for atom in unique if atom.kind is DomainKind.SUFFIX
    }
    ancestor_bases = {
        atom.base
        for atom in unique
        if atom.kind in {DomainKind.SUFFIX, DomainKind.SUBDOMAIN}
    }
    parent_covered = 0
    for candidate in unique:
        same_base_suffix_covers = (
            candidate.kind is not DomainKind.SUFFIX
            and candidate.base in suffix_bases
        )
        ancestor_covers = any(
            ancestor in ancestor_bases
            for ancestor in _strict_ancestor_bases(candidate.base)
        )
        if same_base_suffix_covers or ancestor_covers:
            parent_covered += 1
    return DeduplicationStats(
        input_rules=len(parsed),
        exact_duplicates_removed=len(parsed) - len(unique),
        parent_covered_removed=parent_covered,
        semantic_merges=len(unique) - parent_covered - len(minimized),
        output_rules=len(minimized),
    )


def _is_strict_descendant(child: str, ancestor: str) -> bool:
    return child != ancestor and child.endswith(f".{ancestor}")


def _domain_matches(atom: _DomainAtom, domain: str) -> bool:
    if atom.kind is DomainKind.EXACT:
        return domain == atom.base
    if atom.kind is DomainKind.SUFFIX:
        return domain == atom.base or _is_strict_descendant(domain, atom.base)
    return _is_strict_descendant(domain, atom.base)


def _domain_intersection(
    left: _DomainAtom, right: _DomainAtom
) -> _DomainAtom | None:
    if left.kind is DomainKind.EXACT:
        return left if _domain_matches(right, left.base) else None
    if right.kind is DomainKind.EXACT:
        return right if _domain_matches(left, right.base) else None

    left_below_right = _is_strict_descendant(left.base, right.base)
    right_below_left = _is_strict_descendant(right.base, left.base)
    if left.base != right.base and not left_below_right and not right_below_left:
        return None

    if left.kind is DomainKind.SUFFIX and right.kind is DomainKind.SUFFIX:
        return left if left_below_right or left.base == right.base else right

    if left.kind is DomainKind.SUBDOMAIN and right.kind is DomainKind.SUBDOMAIN:
        return left if left_below_right or left.base == right.base else right

    suffix = left if left.kind is DomainKind.SUFFIX else right
    subdomain = left if left.kind is DomainKind.SUBDOMAIN else right
    if suffix.base == subdomain.base:
        return subdomain
    if _is_strict_descendant(suffix.base, subdomain.base):
        return suffix
    return subdomain


def _domain_contains(container: _DomainAtom, candidate: _DomainAtom) -> bool:
    return _domain_intersection(container, candidate) == candidate


@dataclass(frozen=True)
class _DomainOverlapSummary:
    covers_source: bool
    has_exact_base: bool
    has_subdomain_base: bool
    count: int
    examples: tuple[str, ...]


def _summarize_domain_overlaps(
    index: _DomainIndex,
    source: _DomainAtom,
) -> _DomainOverlapSummary:
    exact_base = _DomainAtom(DomainKind.EXACT, source.base)
    subdomain_base = _DomainAtom(DomainKind.SUBDOMAIN, source.base)
    examples: list[str] = []
    count = 0
    covers_source = False
    has_exact_base = False
    has_subdomain_base = False
    for candidate in index.iter_overlapping(source):
        count += 1
        covers_source = covers_source or _domain_contains(candidate, source)
        has_exact_base = has_exact_base or candidate == exact_base
        has_subdomain_base = has_subdomain_base or candidate == subdomain_base
        rendered = candidate.render()
        if len(examples) < MAX_SETOP_DETAILS:
            insort(examples, rendered)
        elif rendered < examples[-1]:
            insort(examples, rendered)
            examples.pop()
    return _DomainOverlapSummary(
        covers_source=covers_source,
        has_exact_base=has_exact_base,
        has_subdomain_base=has_subdomain_base,
        count=count,
        examples=tuple(examples),
    )


def compute_domain_setops(
    source: Iterable[str], exclude: Iterable[str]
) -> SetOperationResult:
    source_atoms = _normalize_domain_atoms(source, "source")
    exclude_atoms = _normalize_domain_atoms(exclude, "exclude")
    exclude_index = _DomainIndex(exclude_atoms)

    main_atoms: list[_DomainAtom] = []
    removed: list[str] = []
    converted: list[RuleConversion] = []
    partial: list[PartialOverlap] = []

    for source_atom in source_atoms:
        current = source_atom
        while True:
            overlaps = _summarize_domain_overlaps(exclude_index, current)
            if not overlaps.count:
                main_atoms.append(current)
                break

            if overlaps.covers_source:
                removed.append(source_atom.render())
                break

            exact_base = _DomainAtom(DomainKind.EXACT, current.base)
            subdomain_base = _DomainAtom(DomainKind.SUBDOMAIN, current.base)

            if current.kind is DomainKind.SUFFIX and overlaps.has_exact_base:
                replacement = subdomain_base
                converted.append(
                    RuleConversion(
                        source_atom.render(),
                        (replacement.render(),),
                        "exclude_exact_base",
                    )
                )
                current = replacement
                continue

            if current.kind is DomainKind.SUFFIX and overlaps.has_subdomain_base:
                replacement = exact_base
                converted.append(
                    RuleConversion(
                        source_atom.render(),
                        (replacement.render(),),
                        "exclude_all_subdomains",
                    )
                )
                current = replacement
                continue

            main_atoms.append(current)
            partial.append(
                PartialOverlap(
                    current.render(),
                    overlaps.examples,
                    exclusion_count=overlaps.count,
                )
            )
            break

    minimized_main = _minimize_domain_atoms(main_atoms)
    return SetOperationResult(
        behavior="domain",
        source=tuple(atom.render() for atom in source_atoms),
        main=tuple(atom.render() for atom in minimized_main),
        exclude=tuple(atom.render() for atom in exclude_atoms),
        removed=tuple(removed),
        converted=tuple(converted),
        partial_overlap_retained=tuple(partial),
    )


def _parse_ip_rule(value: str) -> IPNetwork:
    if not isinstance(value, str):
        raise SetOperationError("IP rule must be a string")
    rule = value.strip()
    if not rule:
        raise SetOperationError("IP rule must not be empty")
    try:
        return ipaddress.ip_network(rule, strict=False)
    except ValueError as error:
        raise SetOperationError(f"invalid IP rule: {value!r}") from error


def normalize_ip_rule(value: str) -> str:
    """Return one canonical IPv4 or IPv6 network."""

    return str(_parse_ip_rule(value))


def _network_sort_key(network: IPNetwork) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def _collapse_network_objects(networks: Iterable[IPNetwork]) -> tuple[IPNetwork, ...]:
    all_networks = tuple(networks)
    collapsed: list[IPNetwork] = []
    for version in (4, 6):
        family = [network for network in all_networks if network.version == version]
        collapsed.extend(ipaddress.collapse_addresses(family))
    return tuple(sorted(collapsed, key=_network_sort_key))


def _normalize_ip_networks(values: Iterable[str], label: str) -> tuple[IPNetwork, ...]:
    return _collapse_network_objects(
        _parse_ip_rule(value) for value in _rule_values(values, label)
    )


def collapse_ip_rules(values: Iterable[str]) -> tuple[str, ...]:
    """Canonicalize, deduplicate, and collapse IPv4 and IPv6 rules."""

    return tuple(str(network) for network in _normalize_ip_networks(values, "IP rules"))


def _ip_deduplication_stats(values: Iterable[str]) -> DeduplicationStats:
    parsed = tuple(_parse_ip_rule(value) for value in _rule_values(values, "IP rules"))
    unique = set(parsed)
    minimized = _collapse_network_objects(unique)
    parent_covered = 0
    for version in (4, 6):
        family = sorted(
            (network for network in unique if network.version == version),
            key=lambda network: (
                int(network.network_address),
                -int(network.broadcast_address),
            ),
        )
        greatest_end = -1
        for candidate in family:
            candidate_end = int(candidate.broadcast_address)
            if candidate_end <= greatest_end:
                parent_covered += 1
            else:
                greatest_end = candidate_end
    return DeduplicationStats(
        input_rules=len(parsed),
        exact_duplicates_removed=len(parsed) - len(unique),
        parent_covered_removed=parent_covered,
        semantic_merges=len(unique) - parent_covered - len(minimized),
        output_rules=len(minimized),
    )


def _summarize_range(version: int, start: int, end: int) -> list[IPNetwork]:
    address_type = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return list(
        ipaddress.summarize_address_range(address_type(start), address_type(end))
    )


def _extend_ip_output(
    target: list[IPNetwork],
    additions: Sequence[IPNetwork],
) -> None:
    if len(target) + len(additions) > MAX_OUTPUT_RULES:
        raise SetOperationError(
            f"IP difference exceeds the {MAX_OUTPUT_RULES} generated-rule limit"
        )
    target.extend(additions)


def _subtract_ip_family(
    sources: Sequence[IPNetwork], exclusions: Sequence[IPNetwork]
) -> tuple[list[IPNetwork], list[str], list[RuleConversion]]:
    main: list[IPNetwork] = []
    removed: list[str] = []
    converted: list[RuleConversion] = []
    first_exclusion = 0

    for source in sources:
        source_start = int(source.network_address)
        source_end = int(source.broadcast_address)
        while (
            first_exclusion < len(exclusions)
            and int(exclusions[first_exclusion].broadcast_address) < source_start
        ):
            first_exclusion += 1

        cursor = source_start
        exclusion_index = first_exclusion
        pieces: list[IPNetwork] = []
        while exclusion_index < len(exclusions):
            exclusion = exclusions[exclusion_index]
            exclusion_start = int(exclusion.network_address)
            exclusion_end = int(exclusion.broadcast_address)
            if exclusion_start > source_end:
                break
            if exclusion_end < cursor:
                exclusion_index += 1
                continue
            if exclusion_start > cursor:
                _extend_ip_output(
                    pieces,
                    _summarize_range(source.version, cursor, exclusion_start - 1)
                )
            cursor = max(cursor, exclusion_end + 1)
            if cursor > source_end:
                break
            exclusion_index += 1

        if cursor <= source_end:
            _extend_ip_output(
                pieces,
                _summarize_range(source.version, cursor, source_end),
            )

        _extend_ip_output(main, pieces)
        if not pieces:
            removed.append(str(source))
        elif len(pieces) != 1 or pieces[0] != source:
            replacement_count = len(pieces)
            converted.append(
                RuleConversion(
                    str(source),
                    tuple(
                        str(piece)
                        for piece in pieces[:MAX_SETOP_DETAILS]
                    ),
                    "ipcidr_difference",
                    replacement_count=replacement_count,
                )
            )

        while (
            first_exclusion < len(exclusions)
            and int(exclusions[first_exclusion].broadcast_address) <= source_end
        ):
            first_exclusion += 1

    return main, removed, converted


def compute_ip_setops(
    source: Iterable[str], exclude: Iterable[str]
) -> SetOperationResult:
    source_networks = _normalize_ip_networks(source, "source")
    exclude_networks = _normalize_ip_networks(exclude, "exclude")

    main_networks: list[IPNetwork] = []
    removed: list[str] = []
    converted: list[RuleConversion] = []
    for version in (4, 6):
        family_source = [item for item in source_networks if item.version == version]
        family_exclude = [item for item in exclude_networks if item.version == version]
        family_main, family_removed, family_converted = _subtract_ip_family(
            family_source, family_exclude
        )
        main_networks.extend(family_main)
        if len(main_networks) > MAX_OUTPUT_RULES:
            raise SetOperationError(
                f"IP difference exceeds the {MAX_OUTPUT_RULES} generated-rule limit"
            )
        removed.extend(family_removed)
        converted.extend(family_converted)

    return SetOperationResult(
        behavior="ipcidr",
        source=tuple(str(network) for network in source_networks),
        main=tuple(str(network) for network in main_networks),
        exclude=tuple(str(network) for network in exclude_networks),
        removed=tuple(removed),
        converted=tuple(converted),
        partial_overlap_retained=(),
    )


def compute_setops(
    behavior: str, source: Iterable[str], exclude: Iterable[str]
) -> SetOperationResult:
    if not isinstance(behavior, str):
        raise SetOperationError("behavior must be a string")
    normalized_behavior = behavior.strip().lower()
    if normalized_behavior == "domain":
        return compute_domain_setops(source, exclude)
    if normalized_behavior in {"ip", "ipcidr"}:
        return compute_ip_setops(source, exclude)
    raise SetOperationError(f"unsupported behavior: {behavior!r}")


def deduplication_stats(
    behavior: str, values: Iterable[str]
) -> DeduplicationStats:
    if not isinstance(behavior, str):
        raise SetOperationError("behavior must be a string")
    normalized_behavior = behavior.strip().lower()
    if normalized_behavior == "domain":
        return _domain_deduplication_stats(values)
    if normalized_behavior in {"ip", "ipcidr"}:
        return _ip_deduplication_stats(values)
    raise SetOperationError(f"unsupported behavior: {behavior!r}")


__all__ = [
    "DeduplicationStats",
    "DomainKind",
    "PartialOverlap",
    "RuleConversion",
    "SetOperationError",
    "SetOperationResult",
    "collapse_domain_rules",
    "collapse_ip_rules",
    "compute_domain_setops",
    "compute_ip_setops",
    "compute_setops",
    "deduplication_stats",
    "normalize_domain_rule",
    "normalize_ip_rule",
]
