from pathlib import Path

from ai_kavach.patch_gen.cache import PatchCache
from ai_kavach.patch_gen.models import Patch
from ai_kavach.triage import TriagedBug


def create_dummy_bug(func_name: str) -> TriagedBug:
    return TriagedBug(
        crash_type="heap-buffer-overflow",
        top_frames=[func_name, "main"],
        file_path="src/vuln.c",
        line_number=10,
        severity=10,
        hash_signature="hash123",
        original_crashes=[]
    )


def test_cache_miss_and_hit(tmp_path):
    cache = PatchCache(run_id="test_run", output_dir=tmp_path)

    bug1 = create_dummy_bug("vulnerable_func_A")

    # 1. Empty cache miss
    patch_found = cache.check_cache(bug1)
    assert patch_found is None

    # Add a mock successful patch to cache
    good_patch = Patch(
        file_path=Path("src/vuln.c"),
        diff_content="--- a\n+++ b\n+ fix A\n",
        is_template_based=False
    )
    cache.add_to_cache(bug1, good_patch)

    # 2. Second bug with same signature -> hit
    bug2 = create_dummy_bug("vulnerable_func_A")
    patch_found_2 = cache.check_cache(bug2)
    assert patch_found_2 is not None
    assert patch_found_2.diff_content == good_patch.diff_content
    assert patch_found_2.is_cached is True

    # 3. Third bug with different signature -> miss
    bug3 = create_dummy_bug("vulnerable_func_B")
    assert cache.check_cache(bug3) is None


def test_cache_no_collision_across_files_and_lines(tmp_path):
    """Same crash_type+function in different files/lines must not share cache entries."""
    cache = PatchCache(run_id="collision_run", output_dir=tmp_path)

    bug_a = TriagedBug(
        crash_type="heap-buffer-overflow",
        top_frames=["strcpy", "main"],
        file_path="src/a.c",
        line_number=10,
        severity=10,
        hash_signature="hash_a",
        original_crashes=[]
    )
    patch_a = Patch(Path("src/a.c"), "--- a/src/a.c\n+++ b/src/a.c\n+ fix A\n", is_template_based=False)
    cache.add_to_cache(bug_a, patch_a)

    # Same crash type + top frame, different file -> must miss
    bug_b = TriagedBug(
        crash_type="heap-buffer-overflow",
        top_frames=["strcpy", "main"],
        file_path="src/b.c",
        line_number=10,
        severity=10,
        hash_signature="hash_b",
        original_crashes=[]
    )
    assert cache.check_cache(bug_b) is None

    # Same file, different line -> must miss
    bug_c = TriagedBug(
        crash_type="heap-buffer-overflow",
        top_frames=["strcpy", "main"],
        file_path="src/a.c",
        line_number=99,
        severity=10,
        hash_signature="hash_c",
        original_crashes=[]
    )
    assert cache.check_cache(bug_c) is None

    # Exact same location -> hit
    assert cache.check_cache(bug_a) is not None


def test_cache_stale_entry_invalidated_on_source_change(tmp_path):
    """A cached diff must not be served after the source file changes."""
    src_file = tmp_path / "vuln.c"
    src_file.write_text("int main() { return 0; }\n")

    cache = PatchCache(run_id="stale_run", output_dir=tmp_path / "run")
    bug = TriagedBug(
        crash_type="stack-buffer-overflow",
        top_frames=["main"],
        file_path=str(src_file),
        line_number=1,
        severity=10,
        hash_signature="hash_s",
        original_crashes=[]
    )
    patch = Patch(src_file, "--- a\n+++ b\n+ fix\n", is_template_based=False)
    cache.add_to_cache(bug, patch)
    assert cache.check_cache(bug) is not None

    # Mutate the source; the cached diff no longer applies
    src_file.write_text("int main() { return 1; }\n")
    assert cache.check_cache(bug) is None


def test_cache_persistence(tmp_path):
    # Create cache and save an item
    cache1 = PatchCache(run_id="persist_run", output_dir=tmp_path)
    bug = create_dummy_bug("func_C")
    patch = Patch(Path("test.c"), "diff C")
    cache1.add_to_cache(bug, patch)

    # Reload in a new instance
    cache2 = PatchCache(run_id="persist_run", output_dir=tmp_path)

    cached_patch = cache2.check_cache(bug)
    assert cached_patch is not None
    assert cached_patch.diff_content == "diff C"
    assert cached_patch.is_cached is True
