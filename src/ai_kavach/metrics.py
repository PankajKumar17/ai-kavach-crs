"""Metrics instrumentation and reporting module."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class BugResolutionRecord:
    bug_id: str
    resolved: bool
    resolution_path: str  # e.g., "template", "cache", "llm"
    llm_tokens_used: int
    wall_clock_time_s: float
    peak_memory_mb: float | None = None


@dataclass
class RunSummary:
    total_bugs_processed: int
    total_bugs_resolved: int
    tokens_per_verified_patch: float
    average_time_per_verified_patch_s: float
    percent_resolved_without_llm: float
    total_tokens_used: int
    total_time_s: float
    peak_memory_mb: float


def generate_run_summary(records: list[BugResolutionRecord], run_id: str, output_dir: Path) -> RunSummary:
    """
    Generate and save a summary of the metrics for a given run.
    """
    total_bugs = len(records)
    resolved_bugs = [r for r in records if r.resolved]
    total_resolved = len(resolved_bugs)
    
    total_tokens = sum(r.llm_tokens_used for r in records)
    total_time = sum(r.wall_clock_time_s for r in records)
    
    # Peak memory of any record in the run
    peak_memories = [r.peak_memory_mb for r in records if r.peak_memory_mb is not None]
    peak_memory = max(peak_memories) if peak_memories else 0.0
    
    if total_resolved > 0:
        resolved_tokens = sum(r.llm_tokens_used for r in resolved_bugs)
        resolved_time = sum(r.wall_clock_time_s for r in resolved_bugs)
        
        tokens_per_patch = resolved_tokens / total_resolved
        time_per_patch = resolved_time / total_resolved
        
        non_llm_resolutions = [r for r in resolved_bugs if r.resolution_path in ("template", "cache")]
        percent_no_llm = (len(non_llm_resolutions) / total_resolved) * 100.0
    else:
        tokens_per_patch = 0.0
        time_per_patch = 0.0
        percent_no_llm = 0.0
        
    summary = RunSummary(
        total_bugs_processed=total_bugs,
        total_bugs_resolved=total_resolved,
        tokens_per_verified_patch=tokens_per_patch,
        average_time_per_verified_patch_s=time_per_patch,
        percent_resolved_without_llm=percent_no_llm,
        total_tokens_used=total_tokens,
        total_time_s=total_time,
        peak_memory_mb=peak_memory
    )
    
    run_dir = output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.json"
    
    summary_path.write_text(json.dumps(asdict(summary), indent=2))
    
    return summary
