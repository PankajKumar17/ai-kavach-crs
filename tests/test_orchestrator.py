import pytest
from claude_agent_sdk.types import PermissionResultAllow, PermissionResultDeny

from ai_kavach.orchestrator import custom_can_use_tool, set_allowed_patch_files


@pytest.mark.asyncio
async def test_patch_agent_permissions():
    set_allowed_patch_files(["src/vuln.c"])
    
    class MockContext:
        def __init__(self, tool_name, tool_args):
            self.tool_name = tool_name
            self.tool_args = tool_args
            
    # Write to allowed file
    ctx_allow = MockContext("write_file", {"file_path": "src/vuln.c", "content": "fix"})
    res_allow = await custom_can_use_tool(ctx_allow)
    assert isinstance(res_allow, PermissionResultAllow)
    
    # Write to unauthorized file
    ctx_deny = MockContext("write_file", {"file_path": "src/other.c", "content": "fix"})
    res_deny = await custom_can_use_tool(ctx_deny)
    assert isinstance(res_deny, PermissionResultDeny)
    
    # Read-only agent tool check (handled by allowed_tools mostly, but let's test custom_can_use_tool pass-through)
    ctx_other = MockContext("run_fuzzer", {"timeout_s": 10})
    res_other = await custom_can_use_tool(ctx_other)
    assert isinstance(res_other, PermissionResultAllow)
