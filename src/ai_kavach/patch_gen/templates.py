"""Template-based patch generation layer."""

import re
from pathlib import Path

from ai_kavach.patch_gen.models import Patch
from ai_kavach.triage import TriagedBug


def extract_function_body(source: str, function_name: str) -> tuple[str | None, int | None, int | None]:
    """Roughly extract a function body by finding its signature and matching braces."""
    # This is a very simplified regex for C-like function signatures
    pattern = re.compile(r"(\w[\w\s\*&]+)\s+" + re.escape(function_name) + r"\s*\([^)]*\)\s*\{", re.MULTILINE)
    match = pattern.search(source)
    
    if not match:
        return None, None, None
        
    start_idx = match.end() - 1  # Points to the '{'
    
    brace_count = 0
    end_idx = -1
    
    for i, char in enumerate(source[start_idx:], start=start_idx):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                end_idx = i + 1
                break
                
    if end_idx == -1:
        return None, None, None
        
    start_line = source[:start_idx].count('\n') + 1
    end_line = source[:end_idx].count('\n') + 1
    
    return source[start_idx:end_idx], start_line, end_line


def generate_diff(file_path: str, original_source: str, patched_source: str, start_line: int) -> str:
    """Generate a simple unified-diff-like string for the replacement."""
    original_lines = original_source.strip('{} \n').split('\n')
    patched_lines = patched_source.strip('{} \n').split('\n')
    
    # Just a fake simple diff for now that replaces the whole function block
    diff = f"--- a/{file_path}\n+++ b/{file_path}\n"
    diff += f"@@ -{start_line},len +{start_line},len @@\n"
    for line in original_lines:
        diff += f"-{line}\n"
    for line in patched_lines:
        diff += f"+{line}\n"
        
    return diff


def try_template_fix(bug: TriagedBug, source: str) -> Patch | None:
    """
    Attempt to generate a patch using confident templates.
    Returns None if no template confidently matches.
    """
    if not bug.top_frames:
        return None
        
    target_func = bug.top_frames[0]
    func_body, start_line, end_line = extract_function_body(source, target_func)
    
    if not func_body:
        return None

    file_path = bug.file_path
    
    # 1. Missing bounds check before buffer copy (strcpy)
    if "buffer-overflow" in bug.crash_type.lower():
        # Look for strcpy(dest, src)
        strcpy_match = re.search(r"strcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)", func_body)
        if strcpy_match:
            dest = strcpy_match.group(1).strip()
            src = strcpy_match.group(2).strip()
            
            # Very naive bounds fix assuming sizeof(dest) is valid
            # In a real tool, we'd use clang AST to find the actual bound
            # Here we just insert a strncpy or manual check
            
            patched_body = func_body.replace(
                strcpy_match.group(0),
                f"if (strlen({src}) < sizeof({dest})) {{ strcpy({dest}, {src}); }} else {{ /* handle error */ }}"
            )
            
            diff_content = generate_diff(file_path, func_body, patched_body, start_line)
            return Patch(file_path=Path(file_path), diff_content=diff_content, is_template_based=True)

    # 2. Null dereference
    if "null-dereference" in bug.crash_type.lower():
        # This requires much better AST parsing to be confident.
        # We will not confidently match it with regex to avoid bad patches.
        pass
        
    # 3. Integer overflow
    if "integer-overflow" in bug.crash_type.lower():
        pass

    return None
