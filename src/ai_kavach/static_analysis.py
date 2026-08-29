"""Static analysis tools wrapping Semgrep."""

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


def _find_semgrep() -> str | None:
    """
    Locate the semgrep executable.

    Checks PATH first, then falls back to the directory of the active
    interpreter — pip installs semgrep.exe next to python.exe inside a venv,
    and that directory is not always on PATH.
    """
    found = shutil.which("semgrep")
    if found:
        return found
    candidate = Path(sys.executable).parent / "semgrep.exe"
    return str(candidate) if candidate.exists() else None


@dataclass
class StaticFinding:
    rule_id: str
    file_path: Path
    line_number: int
    message: str
    severity: str = "WARNING"  # Semgrep severity: ERROR | WARNING | INFO


def run_static_scan(
    source_dir: Path,
    rulesets: Path | str | list[Path | str],
    excludes: list[str] | None = None,
    extra_configs: list[Path | str] | None = None,
) -> list[StaticFinding]:
    """
    Run a Semgrep scan against a source directory.

    Args:
        source_dir: Path to the target source code.
        rulesets: One or more rule sources — a local YAML path, a Semgrep
            registry ruleset id ("p/python"), or the special value "auto"
            (Semgrep picks rules by languages present in the target).
        excludes: Glob patterns passed as --exclude (e.g. ["dist", "*.min.js"]).
        extra_configs: Additional --config sources appended after `rulesets`
            (e.g. the local custom_rules.yaml alongside "auto").

    Returns:
        List of StaticFinding objects representing potential vulnerabilities.
    """
    semgrep_bin = _find_semgrep()
    if semgrep_bin is None:
        raise RuntimeError("Semgrep is not installed or not on PATH.")

    config_list = list(extra_configs or [])
    if isinstance(rulesets, list):
        config_list = list(rulesets) + config_list
    else:
        config_list.insert(0, rulesets)

    cmd = [semgrep_bin, "scan"]
    for cfg in config_list:
        cmd += ["--config", str(cfg)]
    for pattern in excludes or []:
        cmd += ["--exclude", pattern]
    cmd += ["--json", "--quiet", str(source_dir)]

    result = subprocess.run(cmd, capture_output=True, text=True)

    # Semgrep exit codes:
    # 0 = No findings / success
    # 1 = Findings
    # >1 = Error
    if result.returncode > 1:
        raise RuntimeError(f"Semgrep scan failed:\n{result.stderr}")

    try:
        output_json = json.loads(result.stdout)
    except json.JSONDecodeError:
        if not result.stdout.strip():
            return []
        raise RuntimeError(f"Failed to parse Semgrep output:\n{result.stdout}") from None

    findings = []
    for match in output_json.get("results", []):
        extra = match.get("extra", {})
        findings.append(StaticFinding(
            rule_id=match.get("check_id", "unknown"),
            file_path=Path(match.get("path", "")),
            line_number=match.get("start", {}).get("line", 0),
            message=extra.get("message", ""),
            severity=extra.get("severity", "WARNING"),
        ))

    return findings
