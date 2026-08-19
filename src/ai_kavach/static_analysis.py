"""Static analysis tools wrapping Semgrep."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class StaticFinding:
    rule_id: str
    file_path: Path
    line_number: int
    message: str


def run_static_scan(source_dir: Path, ruleset_path: Path) -> list[StaticFinding]:
    """
    Run a Semgrep scan against a source directory.

    Args:
        source_dir: Path to the target source code.
        ruleset_path: Path to the Semgrep YAML ruleset.

    Returns:
        List of StaticFinding objects representing potential vulnerabilities.
    """
    cmd = [
        "semgrep",
        "scan",
        "--config", str(ruleset_path),
        "--json",
        "--quiet",
        str(source_dir)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Semgrep exit codes:
    # 0 = No findings / success
    # 1 = Findings
    # >1 = Error
    if result.returncode > 1:
        # Check if the error is just missing the executable (like in mock environment)
        if "not recognized as an internal or external command" in result.stderr or "No such file or directory" in result.stderr:
            raise RuntimeError("Semgrep is not installed or not on PATH.")
        raise RuntimeError(f"Semgrep scan failed:\n{result.stderr}")

    try:
        output_json = json.loads(result.stdout)
    except json.JSONDecodeError:
        if not result.stdout.strip():
            return []
        raise RuntimeError(f"Failed to parse Semgrep output:\n{result.stdout}")

    findings = []
    for match in output_json.get("results", []):
        findings.append(StaticFinding(
            rule_id=match.get("check_id", "unknown"),
            file_path=Path(match.get("path", "")),
            line_number=match.get("start", {}).get("line", 0),
            message=match.get("extra", {}).get("message", "")
        ))

    return findings
