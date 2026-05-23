export interface EvidenceRef {
  file_path: string;
  line_number: number | null;
  scanner: string;
  source_url: string;
}

export interface RiskIndicator {
  signal: string;
  recommended_controls: string[];
  threat_id: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  evidence_refs: EvidenceRef[];
}

export interface AgentProfile {
  name: string;
  agent_type: 'supervisor' | 'utility' | 'worker' | 'unknown';
  goal: string;
  capabilities: string[];
  risk_signals: RiskIndicator[];
  skills: string[];
  tools: string[];
  source_file: string;
}

export interface ToolUsage {
  tool_name: string;
  tool_type: string;
  service_category: string;
  source_file: string;
  line_number: number | null;
}

export interface MCPServer {
  name: string;
  transport: string;
  source_file: string;
}

export interface ModelUsage {
  provider: string;
  model_name: string;
  source: string;
  file_path: string;
  line_number: number;
  role: string;
}

export interface Vulnerability {
  cve_id: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  cvss_score: number | null;
  published: string | null;
  summary: string;
  source: string;
  source_url: string | null;
  affected_versions: string | null;
}

export interface ScanReport {
  repo_path: string;
  scan_timestamp: string;
  is_ai_application: boolean;
  confidence: number;
  capability_tags: string[];
  framework: string;
  summary: string;
  agents: AgentProfile[];
  tool_usages: ToolUsage[];
  risk_signals: RiskIndicator[];
  mcp_servers: MCPServer[];
  model_usages: ModelUsage[];
  vulnerabilities: Vulnerability[];
  metadata: Record<string, unknown>;
}

export interface JobStatus {
  job_id: string;
  status: 'pending' | 'running' | 'done' | 'error';
  started_at: string;
  error: string | null;
  result: ScanReport | null;
}
