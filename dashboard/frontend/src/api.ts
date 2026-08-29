export const API_BASE = import.meta.env.VITE_API_BASE || '';

// Target types
export interface TargetCodebase {
  id: string;
  name: string;
  source_type: 'github' | 'zip' | 'local';
  source_url: string | null;
  path: string;
  created_at: string;
  status: 'ready' | 'processing' | 'error';
}

export async function fetchRunSummary(runId: string) {
  const response = await fetch(`${API_BASE}/api/runs/${runId}/summary`);
  if (!response.ok) {
    throw new Error(`Failed to fetch run summary: ${response.statusText}`);
  }
  return response.json();
}

export async function startEngine(authToken?: string, targetId?: string, runId: string = 'test_run') {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${API_BASE}/api/engine/start`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ target_id: targetId, run_id: runId }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || 'Failed to start engine');
  }

  return response.json();
}

export async function runDemo(authToken?: string) {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${API_BASE}/api/engine/demo`, {
    method: 'POST',
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || 'Failed to run demo');
  }

  return response.json();
}

export async function checkHealth() {
  const response = await fetch(`${API_BASE}/health`);
  if (!response.ok) {
    throw new Error('Health check failed');
  }
  return response.json();
}

// Target management
export async function listTargets(): Promise<TargetCodebase[]> {
  const response = await fetch(`${API_BASE}/api/targets`);
  if (!response.ok) {
    throw new Error('Failed to fetch targets');
  }
  const data = await response.json();
  return data.targets;
}

export async function uploadTargetZip(name: string, file: File, authToken?: string): Promise<TargetCodebase> {
  const formData = new FormData();
  formData.append('name', name);
  formData.append('file', file);

  const headers: HeadersInit = {};
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${API_BASE}/api/targets/upload`, {
    method: 'POST',
    headers,
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || 'Failed to upload target');
  }

  const data = await response.json();
  return data.target;
}

export async function createTargetGithub(name: string, githubUrl: string, branch: string = 'main', authToken?: string): Promise<TargetCodebase> {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${API_BASE}/api/targets/github`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name, github_url: githubUrl, branch }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || 'Failed to create GitHub target');
  }

  const data = await response.json();
  return data.target;
}

export async function deleteTarget(targetId: string, authToken?: string): Promise<void> {
  const headers: HeadersInit = {};
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${API_BASE}/api/targets/${targetId}`, {
    method: 'DELETE',
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || 'Failed to delete target');
  }
}

export interface ApplyPatchResult {
  status: string;
  strategy?: string;   // "git_apply" | "manual_replace"
  file: string;
  line_number: number;
  original_line: string;
  patched_line: string;
}

export async function applyPatch(params: {
  targetId: string;
  runId: string;
  vulnId: string;
  filePath: string;
  lineNumber: number;
  originalLine: string;
  patchedLine: string;
  patchDiff?: string;
}): Promise<ApplyPatchResult> {
  const response = await fetch(`${API_BASE}/api/apply-patch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target_id:     params.targetId,
      run_id:        params.runId,
      vuln_id:       params.vulnId,
      file_path:     params.filePath,
      line_number:   params.lineNumber,
      original_line: params.originalLine,
      patched_line:  params.patchedLine,
      patch_diff:    params.patchDiff ?? '',
    }),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || 'Failed to apply patch');
  }
  return response.json();
}