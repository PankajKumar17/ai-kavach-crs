"""Models for patch generation."""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Patch:
    file_path: Path
    diff_content: str
    is_template_based: bool = False
    is_cached: bool = False

    def __post_init__(self):
        # Callers pass triage's str paths directly; coerce so downstream
        # .exists()/.parent calls never hit a bare str.
        if isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)
