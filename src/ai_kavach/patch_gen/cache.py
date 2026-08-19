"""Signature-based instant-fix cache."""

import json
from pathlib import Path

from ai_kavach.patch_gen.models import Patch
from ai_kavach.triage import TriagedBug


class PatchCache:
    """Cache for instant-fix based on vulnerability signature."""
    
    def __init__(self, run_id: str, output_dir: Path = Path("runs")):
        self.run_dir = output_dir / run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.run_dir / "patch_cache.json"
        
        self.cache: dict[str, str] = {}
        self.load()
        
    def load(self):
        """Load cache from disk."""
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text())
                self.cache = data
            except Exception:
                self.cache = {}
                
    def save(self):
        """Persist cache to disk."""
        self.cache_file.write_text(json.dumps(self.cache, indent=2))
        
    def get_signature(self, bug: TriagedBug) -> str:
        """
        Create a signature for a bug.
        Uses crash_type and the first stack frame (usually the vulnerable function).
        """
        # E.g. heap-buffer-overflow:strcpy
        top_frame = bug.top_frames[0] if bug.top_frames else "unknown_func"
        return f"{bug.crash_type}:{top_frame}"
        
    def check_cache(self, bug: TriagedBug) -> Patch | None:
        """Check if a fix exists for this bug signature."""
        sig = self.get_signature(bug)
        if sig in self.cache:
            diff_content = self.cache[sig]
            return Patch(file_path=Path(bug.file_path), diff_content=diff_content, is_template_based=False, is_cached=True)
        return None
        
    def add_to_cache(self, bug: TriagedBug, patch: Patch):
        """Add a successful patch to the cache."""
        sig = self.get_signature(bug)
        self.cache[sig] = patch.diff_content
        self.save()
