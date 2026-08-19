"""Tests for template-based repair."""


from ai_kavach.patch_gen.templates import try_template_fix
from ai_kavach.triage import TriagedBug


def test_try_template_fix_strcpy():
    """Test that it confidently patches a strcpy buffer overflow."""
    source_code = """
#include <string.h>
void vulnerable_func(char *input) {
    char buffer[16];
    strcpy(buffer, input);
}
"""
    
    bug = TriagedBug(
        crash_type="stack-buffer-overflow",
        top_frames=["vulnerable_func", "main"],
        file_path="vuln.c",
        line_number=5,
        severity=10,
        hash_signature="hash123",
        original_crashes=[]
    )
    
    patch = try_template_fix(bug, source_code)
    
    assert patch is not None
    assert patch.is_template_based is True
    assert "vuln.c" in str(patch.file_path)
    assert "strlen(input) < sizeof(buffer)" in patch.diff_content


def test_try_template_fix_unsupported():
    """Test that unsupported bugs return None."""
    source_code = """
void some_func(int *ptr) {
    *ptr = 42;
}
"""
    bug = TriagedBug(
        crash_type="null-dereference",
        top_frames=["some_func"],
        file_path="vuln.c",
        line_number=3,
        severity=7,
        hash_signature="hash123",
        original_crashes=[]
    )
    
    patch = try_template_fix(bug, source_code)
    
    # Should confidently return None instead of guessing
    assert patch is None
