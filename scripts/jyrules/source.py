from __future__ import annotations

import http.client
import ipaddress
import reprlib
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import yaml

from .errors import BuildError
from .model import SourceSpec
from .setops import normalize_domain_rule, normalize_ip_rule


MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_ISSUE_EXAMPLES = 5


@dataclass(frozen=True)
class FetchedSource:
    data: bytes
    locator: str
    final_locator: str
    content_type: str | None


@dataclass
class ParsedSource:
    detected_format: str
    candidates: int = 0
    rules: list[str] = field(default_factory=list)
    issues: Counter[str] = field(default_factory=Counter)
    examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    def issue(self, reason: str, value: str) -> None:
        self.issues[reason] += 1
        if len(self.examples[reason]) < MAX_ISSUE_EXAMPLES:
            self.examples[reason].append(value[:240])

    def issues_json(self) -> dict[str, dict[str, object]]:
        return {
            reason: {
                "count": self.issues[reason],
                "examples": self.examples.get(reason, []),
            }
            for reason in sorted(self.issues)
        }


def _validate_final_https_url(url: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname_value = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise BuildError(f"redirected source is not a valid HTTPS URL: {url}") from exc
    if parsed.scheme.casefold() != "https" or not hostname_value:
        raise BuildError(f"redirected source is not a valid HTTPS URL: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise BuildError(f"redirected source URL contains user information: {url}")
    hostname = hostname_value.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise BuildError(f"redirected source URL is not public: {url}")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if not address.is_global:
        raise BuildError(f"redirected source URL is not public: {url}")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        _validate_final_https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_URL_OPENER = urllib.request.build_opener(_SafeRedirectHandler())


def fetch_source(spec: SourceSpec, repo_root: Path) -> FetchedSource:
    if spec.url is not None:
        _validate_final_https_url(spec.url)
        request = urllib.request.Request(
            spec.url,
            headers={"User-Agent": "JYRules/1.0 (+https://github.com/)"},
        )
        try:
            with _URL_OPENER.open(request, timeout=45) as response:
                final_url = response.geturl()
                _validate_final_https_url(final_url)
                data = response.read(MAX_SOURCE_BYTES + 1)
                content_type = response.headers.get_content_type()
        except (
            OSError,
            urllib.error.URLError,
            http.client.HTTPException,
            UnicodeError,
            ValueError,
        ) as exc:
            raise BuildError(f"failed to download {spec.url}: {exc}") from exc
        if len(data) > MAX_SOURCE_BYTES:
            raise BuildError(f"source exceeds {MAX_SOURCE_BYTES} bytes: {spec.url}")
        return FetchedSource(data, spec.url, final_url, content_type)

    if spec.path is None:
        raise BuildError("source has neither url nor path")
    root = repo_root.resolve()
    path = (root / spec.path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise BuildError(f"local source escapes repository root: {spec.path}") from exc
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BuildError(f"failed to read local source {spec.path}: {exc}") from exc
    if len(data) > MAX_SOURCE_BYTES:
        raise BuildError(f"source exceeds {MAX_SOURCE_BYTES} bytes: {spec.path}")
    return FetchedSource(data, spec.path, spec.path, None)


def _decode_utf8(data: bytes, locator: str) -> str:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BuildError(f"source is not valid UTF-8 text: {locator}: {exc}") from exc
    if "\x00" in text:
        raise BuildError(f"source contains NUL bytes: {locator}")
    stripped = text.lstrip().lower()
    if stripped.startswith("<!doctype html") or stripped.startswith("<html"):
        raise BuildError(f"source returned HTML instead of rules: {locator}")
    return text


def _is_probably_binary(data: bytes) -> bool:
    sample = data[:4096]
    if b"\x00" in sample:
        return True
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _first_content_line(text: str) -> str:
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith(("#", "//", ";", "!")):
            return line
    return ""


def _looks_structured_yaml(text: str) -> bool:
    first = _first_content_line(text)
    lowered = first.lower()
    if (
        lowered in {"---", "payload:", "rules:"}
        or lowered.startswith(("payload: ", "rules: "))
        or first.startswith(("%YAML", "- ", "[", "{"))
    ):
        return True
    for raw in text.splitlines():
        if raw != raw.lstrip():
            continue
        line = raw.strip().casefold()
        if line == "payload:" or line == "rules:":
            return True
        if line.startswith(("payload: ", "rules: ")):
            return True
    return False


def _yaml_rule_values(
    text: str, locator: str, *, required: bool
) -> list[object] | None:
    try:
        value = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        if required or _looks_structured_yaml(text):
            raise BuildError(f"invalid YAML source {locator}: {exc}") from exc
        return None
    if isinstance(value, dict):
        if "payload" in value:
            value = value["payload"]
        elif "rules" in value:
            value = value["rules"]
        else:
            if required:
                raise BuildError(f"YAML source has neither payload nor rules: {locator}")
            return None
    elif not isinstance(value, list):
        if required:
            raise BuildError(f"YAML rules must be a list: {locator}")
        return None
    if value is None:
        return []
    if not isinstance(value, list):
        raise BuildError(f"YAML rules must be a list: {locator}")
    return value


def _text_rule_values(text: str) -> list[str]:
    values: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "//", ";", "!")):
            continue
        values.append(line)
    return values


def _classical_parts(line: str) -> tuple[str, str, list[str]] | None:
    if "," not in line:
        return None
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2:
        return None
    return parts[0].upper(), parts[1], parts[2:]


def _try_domain(value: str) -> str | None:
    try:
        return normalize_domain_rule(value)
    except ValueError:
        return None


def _try_ip(value: str) -> str | None:
    try:
        return normalize_ip_rule(value)
    except ValueError:
        return None


def _parse_rule_value(
    result: ParsedSource,
    value: object,
    behavior: str,
    *,
    behavior_is_explicit: bool = False,
) -> None:
    if not isinstance(value, str):
        result.issue("non_string_rule", reprlib.repr(value))
        return
    line = value.strip()
    if not line or line.startswith(("#", "//", ";", "!")):
        return
    result.candidates += 1
    classical = _classical_parts(line)

    if classical is None:
        if behavior == "domain":
            if not behavior_is_explicit and _try_ip(line) is not None:
                result.issue("other_behavior:ipcidr", line)
            else:
                normalized = _try_domain(line)
                if normalized is not None:
                    result.rules.append(normalized)
                else:
                    result.issue("invalid_domain", line)
        else:
            normalized = _try_ip(line)
            if normalized is not None:
                result.rules.append(normalized)
            elif _try_domain(line) is not None:
                result.issue("other_behavior:domain", line)
            else:
                result.issue("invalid_ipcidr", line)
        return

    rule_type, payload, params = classical
    if not payload:
        result.issue("missing_payload", line)
        return

    if behavior == "domain":
        if rule_type == "DOMAIN":
            normalized = _try_domain(payload)
        elif rule_type == "DOMAIN-SUFFIX":
            normalized = _try_domain(f"+.{payload.lstrip('.')}")
        elif rule_type in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6"}:
            result.issue(f"other_behavior:{rule_type}", line)
            return
        else:
            result.issue(f"unsupported_rule_type:{rule_type}", line)
            return
        if normalized is None:
            result.issue("invalid_domain", line)
        else:
            result.rules.append(normalized)
        return

    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        if any(param.casefold() == "src" for param in params):
            result.issue("unsupported_source_ipcidr", line)
            return
        normalized = _try_ip(payload)
        if normalized is None:
            result.issue("invalid_ipcidr", line)
        else:
            result.rules.append(normalized)
    elif rule_type.startswith("DOMAIN"):
        result.issue(f"other_behavior:{rule_type}", line)
    else:
        result.issue(f"unsupported_rule_type:{rule_type}", line)


def parse_source_data(
    fetched: FetchedSource,
    behavior: str,
    declared_format: str,
    mrs_decoder: Callable[[bytes, str], str] | None = None,
) -> ParsedSource:
    source_format = "text" if declared_format == "list" else declared_format
    if source_format not in {"auto", "mrs", "yaml", "text"}:
        raise BuildError(f"unsupported source format: {declared_format}")

    if source_format == "mrs" or (source_format == "auto" and _is_probably_binary(fetched.data)):
        if mrs_decoder is None:
            raise BuildError(f"MRS decoder is unavailable for {fetched.locator}")
        text = mrs_decoder(fetched.data, behavior)
        detected = "mrs"
        values: Iterable[object] = _text_rule_values(text)
    else:
        text = _decode_utf8(fetched.data, fetched.locator)
        if source_format == "text":
            values = _text_rule_values(text)
            detected = "text"
        else:
            yaml_values = _yaml_rule_values(
                text,
                fetched.locator,
                required=source_format == "yaml",
            )
            if yaml_values is not None:
                values = yaml_values
                detected = "yaml"
            else:
                values = _text_rule_values(text)
                detected = "text"

    result = ParsedSource(detected_format=detected)
    for value in values:
        _parse_rule_value(
            result,
            value,
            behavior,
            behavior_is_explicit=detected == "mrs",
        )
    return result
