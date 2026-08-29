export interface RunSummary {
  total_bugs_processed: number;
  total_bugs_resolved: number;
  tokens_per_verified_patch: number;
  average_time_per_verified_patch_s: number;
  percent_resolved_without_llm: number;
  total_tokens_used: number;
  total_time_s: number;
  peak_memory_mb: number;
  run_id?: string;
  status?: string;
  timestamp?: string;
  vulnerabilities?: Vulnerability[];
  agent_trace?: string[];
}

export interface Vulnerability {
  id: string;
  type: string;
  location: string;
  line_text?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'Resolved' | 'Failed' | 'Pending' | 'Failed (Timeout)' | 'False Positive';
  agent: string;
  time_taken: string;
  rca?: string;
  fix_hint?: string;
  // Patch fields
  patched_line?: string;     // single-line alias (kept for backwards compat)
  patch_diff?: string;       // unified diff (preferred)
  patch_tier?: 'template' | 'cached' | 'llm' | 'none';
  file_path?: string;
  line_number?: number;
  // RCA enrichment
  cwe?: string;              // e.g. "CWE-330"
  fix_location?: string;     // "crash_site" | "earlier_in_chain"
  // Critic
  critic_verdict?: string;   // "approved" | "concern: ..." | "critic_unavailable: ..."
  // Fuzzing evidence (C pipeline)
  asan_trace?: string;       // raw sanitizer output of the crash
  crash_count?: number;
}

export interface EngineStartResponse {
  status: string;
  trace: string[];
  exit_code?: number;
  target_id?: string | null;
}

export interface TargetCodebase {
  id: string;
  name: string;
  source_type: 'github' | 'zip' | 'local';
  source_url: string | null;
  path: string;
  created_at: string;
  status: 'ready' | 'processing' | 'error';
}