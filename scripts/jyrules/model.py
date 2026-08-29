from __future__ import annotations

import ipaddress
import re
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping

from .errors import TaskConfigError


Behavior = Literal["domain", "ipcidr"]
OutputDirectory = Literal["domain", "ip"]
SourceFormat = Literal["auto", "mrs", "yaml", "text", "list"]
SourceKind = Literal["url", "path"]

_TASK_FIELDS = frozenset({"version", "enabled", "behavior", "output", "sources", "exclude"})
_SOURCE_FIELDS = frozenset({"name", "url", "path", "format", "optional"})
_BEHAVIORS: dict[str, Behavior] = {
    "domain": "domain",
    "ip": "ipcidr",
    "ipcidr": "ipcidr",
}
_OUTPUT_DIRECTORIES: dict[Behavior, OutputDirectory] = {
    "domain": "domain",
    "ipcidr": "ip",
}
_SOURCE_FORMATS = frozenset({"auto", "mrs", "yaml", "text", "list"})
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)
_WINDOWS_ILLEGAL = frozenset('<>:"/\\|?*')
_HOST_LABEL = re.compile(r"^[A-Za-z0-9-]+$")


@dataclass(frozen=True, slots=True)
class SourceSpec:
    name: str | None
    url: str | None
    path: str | None
    format: SourceFormat
    optional: bool

    @property
    def kind(self) -> SourceKind:
        return "url" if self.url is not None else "path"

    @property
    def locator(self) -> str:
        value = self.url if self.url is not None else self.path
        if value is None:  # Construction through load_tasks always sets one.
            raise RuntimeError("source has neither a URL nor a path")
        return value


@dataclass(frozen=True, slots=True)
class Task:
    name: str
    definition_path: Path
    version: int
    enabled: bool
    behavior: Behavior
    output: str
    sources: tuple[SourceSpec, ...]
    exclude: tuple[SourceSpec, ...]

    @property
    def output_directory(self) -> OutputDirectory:
        return _OUTPUT_DIRECTORIES[self.behavior]


def _fail(path: Path, field: str | None, message: str) -> None:
    raise TaskConfigError(message, path=path, field=field)


def _reject_unknown(
    value: Mapping[str, object],
    allowed: frozenset[str],
    *,
    path: Path,
    field: str | None,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        label = "fields" if len(unknown) > 1 else "field"
        _fail(path, field, f"unknown {label}: {', '.join(unknown)}")


def _required_string(value: object, *, path: Path, field: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(path, field, "must be a non-empty string")
    if value != value.strip() or any(ord(character) < 32 for character in value):
        _fail(path, field, "must not contain surrounding whitespace or control characters")
    return value


def _validate_windows_component(value: str, *, path: Path, field: str) -> str:
    if value in {".", ".."} or not value:
        _fail(path, field, "must be a non-empty file name")
    if value.endswith((" ", ".")):
        _fail(path, field, "must not end with a space or period")
    if any(ord(character) < 32 or character in _WINDOWS_ILLEGAL for character in value):
        _fail(path, field, "contains a Windows-illegal file name character")
    if value.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
        _fail(path, field, "uses a Windows-reserved file name")
    if value.casefold() == ".git":
        _fail(path, field, "must not refer to .git")
    return value


def _validate_output(value: object, *, path: Path) -> str:
    output = _required_string(value, path=path, field="output")
    if "/" in output or "\\" in output:
        _fail(path, "output", "must be a single file stem, not a path")
    if output.startswith("."):
        _fail(path, "output", "must not be a hidden file name")
    _validate_windows_component(output, path=path, field="output")
    if output.casefold().endswith((".mrs", ".txt")):
        _fail(path, "output", "must omit the generated .mrs or .txt extension")
    return output


def _validate_relative_path(value: object, *, task_path: Path, field: str) -> str:
    raw = _required_string(value, path=task_path, field=field)
    normalized = raw.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        _fail(task_path, field, "must be a repository-relative path")
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _fail(task_path, field, "must not contain empty, current, or parent path segments")
    for part in parts:
        _validate_windows_component(part, path=task_path, field=field)
    return "/".join(parts)


def _validate_public_https_url(value: object, *, task_path: Path, field: str) -> str:
    url = _required_string(value, path=task_path, field=field)
    if "\\" in url or any(character.isspace() for character in url):
        _fail(task_path, field, "must be a valid HTTPS URL without whitespace or backslashes")
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        _fail(task_path, field, f"must be a valid HTTPS URL: {exc}")
    if parsed.scheme.casefold() != "https" or not parsed.netloc or hostname is None:
        _fail(task_path, field, "must use HTTPS and include a public hostname")
    if parsed.username is not None or parsed.password is not None:
        _fail(task_path, field, "must not contain user information")

    hostname = hostname.rstrip(".")
    if not hostname:
        _fail(task_path, field, "must include a public hostname")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        lowered = hostname.casefold()
        if lowered == "localhost" or lowered.endswith(".localhost"):
            _fail(task_path, field, "hostname is not public")
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            _fail(task_path, field, "contains an invalid hostname")
        labels = ascii_hostname.split(".")
        if (
            len(labels) < 2
            or all(label.isdigit() for label in labels)
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or _HOST_LABEL.fullmatch(label) is None
                for label in labels
            )
        ):
            _fail(task_path, field, "must include a valid public hostname")
        canonical_hostname = ascii_hostname.casefold()
    else:
        if not address.is_global:
            _fail(task_path, field, "IP address is not public")
        canonical_hostname = str(address)

    if ":" in canonical_hostname:
        canonical_hostname = f"[{canonical_hostname}]"
    netloc = canonical_hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    safe_path = urllib.parse.quote(
        parsed.path,
        safe="/%:@!$&'()*+,;=-._~",
    )
    safe_query = urllib.parse.quote(
        parsed.query,
        safe="/%?:@!$&'()*+,;=-._~",
    )
    safe_fragment = urllib.parse.quote(
        parsed.fragment,
        safe="/%?:@!$&'()*+,;=-._~",
    )
    return urllib.parse.urlunsplit(
        ("https", netloc, safe_path, safe_query, safe_fragment)
    )


def _parse_source(value: object, *, task_path: Path, field: str) -> SourceSpec:
    if not isinstance(value, dict):
        _fail(task_path, field, "must be a table")
    _reject_unknown(value, _SOURCE_FIELDS, path=task_path, field=field)

    has_url = "url" in value
    has_path = "path" in value
    if has_url == has_path:
        _fail(task_path, field, "must define exactly one of url or path")

    name_value = value.get("name")
    name = None
    if name_value is not None:
        name = _required_string(name_value, path=task_path, field=f"{field}.name")

    format_value = value.get("format", "auto")
    if not isinstance(format_value, str):
        _fail(task_path, f"{field}.format", "must be a string")
    source_format = format_value.casefold()
    if source_format not in _SOURCE_FORMATS:
        _fail(
            task_path,
            f"{field}.format",
            "must be one of auto, mrs, yaml, text, or list",
        )

    optional = value.get("optional", False)
    if not isinstance(optional, bool):
        _fail(task_path, f"{field}.optional", "must be true or false")

    url = None
    local_path = None
    if has_url:
        url = _validate_public_https_url(value["url"], task_path=task_path, field=f"{field}.url")
    else:
        local_path = _validate_relative_path(
            value["path"],
            task_path=task_path,
            field=f"{field}.path",
        )

    return SourceSpec(
        name=name,
        url=url,
        path=local_path,
        format=source_format,  # type: ignore[arg-type]
        optional=optional,
    )


def _parse_source_list(
    value: object,
    *,
    task_path: Path,
    field: str,
    required: bool,
) -> tuple[SourceSpec, ...]:
    if not isinstance(value, list):
        _fail(task_path, field, "must be an array of tables")
    if required and not value:
        _fail(task_path, field, "must contain at least one source")
    return tuple(
        _parse_source(item, task_path=task_path, field=f"{field}[{index}]")
        for index, item in enumerate(value, start=1)
    )


def _load_task(task_path: Path) -> Task:
    try:
        with task_path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise TaskConfigError(f"cannot read TOML: {exc}", path=task_path) from exc

    _reject_unknown(value, _TASK_FIELDS, path=task_path, field=None)

    version = value.get("version")
    if type(version) is not int or version != 1:
        _fail(task_path, "version", "must be the integer 1")

    enabled = value.get("enabled", True)
    if not isinstance(enabled, bool):
        _fail(task_path, "enabled", "must be true or false")

    behavior_value = value.get("behavior")
    if not isinstance(behavior_value, str):
        _fail(task_path, "behavior", "must be domain, ipcidr, or the ip alias")
    behavior = _BEHAVIORS.get(behavior_value.casefold())
    if behavior is None:
        _fail(task_path, "behavior", "must be domain, ipcidr, or the ip alias")

    if "output" not in value:
        _fail(task_path, "output", "is required")
    output = _validate_output(value["output"], path=task_path)

    if "sources" not in value:
        _fail(task_path, "sources", "is required")
    sources = _parse_source_list(
        value["sources"],
        task_path=task_path,
        field="sources",
        required=True,
    )
    exclude = _parse_source_list(
        value.get("exclude", []),
        task_path=task_path,
        field="exclude",
        required=False,
    )

    task_name = task_path.name[: -len(task_path.suffix)]
    _validate_windows_component(task_name, path=task_path, field="task filename")
    return Task(
        name=task_name,
        definition_path=task_path,
        version=version,
        enabled=enabled,
        behavior=behavior,
        output=output,
        sources=sources,
        exclude=exclude,
    )


def load_tasks(tasks_dir: str | Path) -> tuple[Task, ...]:
    """Load and validate direct ``*.toml`` children of *tasks_dir*."""

    task_root = Path(tasks_dir).resolve()
    if not task_root.exists():
        return ()
    if not task_root.is_dir():
        raise TaskConfigError("tasks must be a directory", path=task_root)

    task_paths = sorted(
        (
            path
            for path in task_root.iterdir()
            if path.is_file() and path.suffix.casefold() == ".toml"
        ),
        key=lambda path: (path.name.casefold(), path.name),
    )
    tasks = tuple(_load_task(path) for path in task_paths)

    task_names: dict[str, Task] = {}
    output_claims: dict[tuple[OutputDirectory, str], tuple[Task, str]] = {}
    for task in tasks:
        name_key = task.name.casefold()
        if name_key in task_names:
            previous = task_names[name_key]
            raise TaskConfigError(
                f"task name conflicts case-insensitively with {previous.definition_path.name}",
                path=task.definition_path,
                field="task filename",
            )
        task_names[name_key] = task

        stems = [(task.output, "output")]
        if task.exclude:
            stems.append((f"NO_{task.output}", "exclude output"))
        for stem, label in stems:
            key = (task.output_directory, stem.casefold())
            if key in output_claims:
                previous, previous_label = output_claims[key]
                raise TaskConfigError(
                    f"{label} {stem!r} in rules/{task.output_directory} conflicts "
                    f"case-insensitively with "
                    f"{previous_label} from {previous.definition_path.name}",
                    path=task.definition_path,
                    field="output",
                )
            output_claims[key] = (task, label)

    return tasks
