"""Instrumentation module for building targets with ASan/UBSan."""

import os
import subprocess
from pathlib import Path


class BuildError(Exception):
    """Custom exception raised when target building fails."""


def build_target(source_dir: Path, sanitizers: list[str] = None) -> Path:
    """
    Build a target directory with the given sanitizers.
    
    Args:
        source_dir: Path to the target source code.
        sanitizers: List of sanitizers to enable (default: ["address", "undefined"]).
        
    Returns:
        Path to the compiled executable.
        
    Raises:
        BuildError: If compilation fails.
    """
    if sanitizers is None:
        sanitizers = ["address", "undefined"]
        
    if not source_dir.exists() or not source_dir.is_dir():
        raise BuildError(f"Source directory does not exist or is not a directory: {source_dir}")

    sanitizer_flag = ",".join(sanitizers)
    
    if os.name == "nt":
        script_path = source_dir.parent / "build_target.ps1"
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-SourceDir", str(source_dir), "-Sanitizers", sanitizer_flag]
    else:
        script_path = source_dir.parent / "build_target.sh"
        cmd = ["bash", str(script_path), str(source_dir), sanitizer_flag]

    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise BuildError(f"Build failed for {source_dir}:\n{result.stderr}\n{result.stdout}")
        
    # The script outputs the path to the binary on the last line
    output_lines = result.stdout.strip().split("\n")
    bin_path = Path(output_lines[-1].strip())
    
    if not bin_path.exists():
        raise BuildError(f"Build succeeded but output binary not found at {bin_path}")
        
    return bin_path
