"""Models for patch generation."""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Patch:
    file_path: Path
    diff_content: str
    is_template_based: bool = False
    is_cached: bool = False
