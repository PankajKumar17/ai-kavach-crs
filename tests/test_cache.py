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
