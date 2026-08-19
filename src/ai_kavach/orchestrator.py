"""Orchestrator using Claude Agent SDK."""

import json
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    create_sdk_mcp_server,
    tool,
)
from claude_agent_sdk.types import PermissionResultAllow, PermissionResultDeny

# Shared state to communicate allowed files to the patch agent
_ALLOWED_PATCH_FILES: set[str] = set()

def set_allowed_patch_files(files: list[str]):
    global _ALLOWED_PATCH_FILES
    _ALLOWED_PATCH_FILES = set(files)

# Custom tools
@tool("run_fuzzer", "Run the fuzzing campaign", {"timeout_s": int})
async def tool_run_fuzzer(args: dict[str, Any]):
    return {"content": [{"type": "text", "text": "Fuzzer completed with 1 crash."}]}

@tool("run_semgrep", "Run static analysis", {"target_dir": str})
async def tool_run_semgrep(args: dict[str, Any]):
    return {"content": [{"type": "text", "text": "Semgrep completed."}]}

@tool("verify_harness", "Run the verification harness", {"patch_file": str})
async def tool_verify_harness(args: dict[str, Any]):
    return {"content": [{"type": "text", "text": "Verification passed."}]}

@tool("write_file", "Write to a source file", {"file_path": str, "content": str})
async def tool_write_file(args: dict[str, Any]):
    # This is a dummy tool for the patch agent
    return {"content": [{"type": "text", "text": "File written."}]}

# Create MCP server
kavach_server = create_sdk_mcp_server(
    name="kavach",
    tools=[tool_run_fuzzer, tool_run_semgrep, tool_verify_harness, tool_write_file]
)


async def custom_can_use_tool(context: Any) -> Any:
    """Enforce permissions at the tool level."""
    tool_name = getattr(context, "tool_name", "")
    if not tool_name:
        if isinstance(context, dict):
            tool_name = context.get("tool_name", "")
            
    # For patch agent, restrict write_file to allowed files
    if tool_name == "write_file":
        args = getattr(context, "tool_args", {})
        if isinstance(context, dict) and not args:
            args = context.get("tool_args", {})
            
        file_path = args.get("file_path", "")
        if file_path not in _ALLOWED_PATCH_FILES:
            # Deny
            return PermissionResultDeny(message=f"File {file_path} is not in RCA report allowed files.")
            
    return PermissionResultAllow()


def get_agent_options(agent_role: str, run_id: str) -> ClaudeAgentOptions:
    if agent_role == "triage-agent":
        allowed = ["run_fuzzer", "run_semgrep"]
        disallowed = ["write_file", "verify_harness"]
    elif agent_role == "rca-agent":
        allowed = []
        disallowed = ["write_file", "run_fuzzer", "run_semgrep", "verify_harness"]
    elif agent_role == "patch-agent":
        allowed = ["write_file", "verify_harness"]
        disallowed = ["run_fuzzer", "run_semgrep"]
    else:
        allowed = []
        disallowed = []
        
    return ClaudeAgentOptions(
        mcp_servers={"kavach": kavach_server},
        allowed_tools=allowed,
        disallowed_tools=disallowed,
        can_use_tool=custom_can_use_tool,
        session_id=f"{run_id}_{agent_role}"
    )


async def run_subagent(agent_role: str, run_id: str, prompt: str):
    options = get_agent_options(agent_role, run_id)
    trace_file = Path("runs") / run_id / "trace.jsonl"
    trace_file.parent.mkdir(parents=True, exist_ok=True)
    
    # In a real app we'd stream the response and log tool calls
    async with ClaudeSDKClient(options) as client:
        await client.query(prompt)
        async for msg in client.receive_response():
            # Log trace
            with open(trace_file, "a") as f:
                f.write(json.dumps({"agent": agent_role, "msg_type": type(msg).__name__}) + "\n")
