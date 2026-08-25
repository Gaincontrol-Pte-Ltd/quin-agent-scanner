import type { JobStatus } from './types';

const BASE = '/api';

export interface ScanOptions {
  target: string;
  no_llm?: boolean;
  llm_provider?: string;
  github_token?: string;
  branch?: string;
  min_confidence?: number;
  no_vuln_check?: boolean;
}

function normalizeTarget(target: string): string {
  // Upgrade owner/repo shorthand to full HTTPS URL so git clone is used
  // (avoids Python SSL cert issues on macOS with the API-based accessor)
  if (/^[\w.-]+\/[\w.-]+$/.test(target)) {
    return `https://github.com/${target}`;
  }
  return target;
}

export async function startScan(opts: ScanOptions): Promise<{ job_id: string }> {
  const res = await fetch(`${BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...opts, target: normalizeTarget(opts.target) }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? 'Failed to start scan');
  }
  return res.json();
}

export async function pollJob(jobId: string): Promise<JobStatus> {
  const res = await fetch(`${BASE}/scan/${jobId}`);
  if (!res.ok) throw new Error(`Job ${jobId} not found`);
  return res.json();
}
