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

        # Cache format: {signature: {"diff": str, "source_hash": str}}
        self.cache: dict[str, dict] = {}
        self.load()

    def load(self):
        """Load cache from disk."""
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text())
                if isinstance(data, dict):
                    self.cache = data
                else:
                    self.cache = {}
            except Exception:
                self.cache = {}

    def save(self):
        """Persist cache to disk atomically."""
        import os
        import tempfile

        # Write to temp file then rename for atomicity
        fd, tmp_path = tempfile.mkstemp(dir=self.run_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(self.cache, f, indent=2)
            os.replace(tmp_path, self.cache_file)
        except Exception:
            # Fall back to non-atomic write
            self.cache_file.write_text(json.dumps(self.cache, indent=2))

    def get_signature(self, bug: TriagedBug) -> str:
        """
        Create a signature for a bug.

        Includes crash_type, top frame, file path, and line number so that
        a cached diff is only served for the exact same location. Without
        file/line, "heap-buffer-overflow:strcpy" collides across every file.
        """
        top_frame = bug.top_frames[0] if bug.top_frames else "unknown_func"
        # Normalize file path to forward slashes for cross-platform consistency
        file_path = Path(bug.file_path).as_posix()
        return f"{bug.crash_type}:{top_frame}:{file_path}:{bug.line_number}"

    def check_cache(self, bug: TriagedBug) -> Patch | None:
        """Check if a fix exists for this bug signature."""
        sig = self.get_signature(bug)
        if sig not in self.cache:
            return None

        entry = self.cache[sig]
        if not isinstance(entry, dict) or "diff" not in entry:
            # Legacy format - treat as valid but don't verify staleness
            diff_content = entry if isinstance(entry, str) else ""
            return Patch(
                file_path=Path(bug.file_path), diff_content=diff_content,
                is_template_based=False, is_cached=True,
            )

        # Check for source file staleness
        source_hash = entry.get("source_hash")
        if source_hash:
            try:
                import hashlib
                current_hash = hashlib.sha256(Path(bug.file_path).read_bytes()).hexdigest()[:16]
                if current_hash != source_hash:
                    # Source file has changed - cache entry is stale
                    return None
            except Exception:
                # Can't read source file - proceed with cached diff anyway
                pass

        return Patch(file_path=Path(bug.file_path), diff_content=entry["diff"], is_template_based=False, is_cached=True)

    def add_to_cache(self, bug: TriagedBug, patch: Patch):
        """Add a successful patch to the cache with source file hash."""
        import hashlib

        sig = self.get_signature(bug)

        # Compute hash of source file for staleness detection
        source_hash = None
        try:
            source_hash = hashlib.sha256(Path(bug.file_path).read_bytes()).hexdigest()[:16]
        except Exception:
            pass

        self.cache[sig] = {
            "diff": patch.diff_content,
            "source_hash": source_hash
        }
        self.save()
