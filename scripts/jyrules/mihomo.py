from __future__ import annotations

import subprocess
from pathlib import Path

from .errors import BuildError
from .mrs import decode_domain_mrs
from .setops import compute_setops


class MihomoConverter:
    def __init__(self, executable: Path, work_dir: Path) -> None:
        self.executable = executable.resolve()
        self.work_dir = work_dir.resolve()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        if not self.executable.is_file():
            raise BuildError(f"Mihomo executable does not exist: {self.executable}")
        self._counter = 0

    def _token(self, behavior: str) -> str:
        self._counter += 1
        return f"{self._counter:05d}-{behavior}"

    def _run(self, behavior: str, source_format: str, source: Path, target: Path) -> str:
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                [
                    str(self.executable),
                    "convert-ruleset",
                    behavior,
                    source_format,
                    str(source),
                    str(target),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            target.unlink(missing_ok=True)
            raise BuildError(f"failed to run Mihomo for {source}: {exc}") from exc
        log = result.stdout or ""
        invalid_warning = "invalid domain" in log.casefold() or "invalid ipcidr" in log.casefold()
        if result.returncode != 0 or invalid_warning or not target.is_file():
            target.unlink(missing_ok=True)
            raise BuildError(
                f"Mihomo conversion failed ({behavior}/{source_format}, exit {result.returncode}) "
                f"for {source}: {log.strip()}"
            )
        return log

    def decode_mrs(self, data: bytes, behavior: str) -> str:
        if behavior == "domain":
            entries = decode_domain_mrs(data)
            return "".join(f"{entry}\n" for entry in entries)

        token = self._token(behavior)
        source = self.work_dir / f"{token}.mrs"
        target = self.work_dir / f"{token}.txt"
        source.write_bytes(data)
        self._run(behavior, "mrs", source, target)
        try:
            return target.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            raise BuildError(f"cannot read Mihomo MRS dump for {source}: {exc}") from exc

    def compile_and_verify(
        self,
        entries: tuple[str, ...],
        behavior: str,
        text_target: Path,
        mrs_target: Path,
    ) -> None:
        if not entries:
            raise BuildError(f"refusing to create an empty {behavior} MRS: {mrs_target}")
        text_target.parent.mkdir(parents=True, exist_ok=True)
        text_target.write_text(
            "".join(f"{entry}\n" for entry in entries),
            encoding="utf-8",
            newline="\n",
        )
        self._run(behavior, "text", text_target, mrs_target)
        if mrs_target.stat().st_size == 0:
            mrs_target.unlink(missing_ok=True)
            raise BuildError(f"Mihomo produced an empty MRS: {mrs_target}")

        dumped = self.decode_mrs(mrs_target.read_bytes(), behavior)
        dumped_entries = tuple(line.strip() for line in dumped.splitlines() if line.strip())
        expected = compute_setops(behavior, entries, ()).source
        actual = compute_setops(behavior, dumped_entries, ()).source
        if actual != expected:
            mrs_target.unlink(missing_ok=True)
            raise BuildError(
                f"MRS round-trip changed the matching set for {mrs_target}: "
                f"expected {len(expected)}, got {len(actual)}"
            )
