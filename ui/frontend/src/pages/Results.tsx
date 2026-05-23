import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Bot, Shield, Wrench, Server, Cpu, AlertTriangle, CheckCircle,
  ExternalLink, ChevronDown, ChevronUp,
} from 'lucide-react';
import { pollJob } from '../api';
import type { ScanReport, AgentProfile, RiskIndicator, Vulnerability, ToolUsage, MCPServer, ModelUsage } from '../types';

/* ── Design tokens — gaincontrol.ai/quin theme ─── */
const T = {
  bg:       '#0B0F1E',
  surface:  '#12172B',
  surfaceHi:'#171d34',
  border:   '#24293D',
  borderHi: 'rgba(243,162,22,0.22)',
  text:     '#EAEAF1',
  muted:    '#8181A2',
  quin:     '#F3A216',
  quinDim:  'rgba(243,162,22,0.1)',
  primary:  '#875BF1',
  high:     '#ef4444',
  medium:   '#f59e0b',
  low:      '#22c55e',
};

const HEADER_BG = 'radial-gradient(ellipse 80% 60% at 50% -10%, rgba(135,91,241,0.18) 0%, transparent 60%), linear-gradient(160deg, #0B0F1E 0%, #0e1228 55%, #100d1f 100%)';

/* ── Severity helpers (dark-mode) ──────────── */
const SEV: Record<string, { bg: string; border: string; text: string; badgeBg: string; badgeText: string }> = {
  critical: { bg: 'rgba(185,28,28,0.15)',  border: 'rgba(185,28,28,0.4)',   text: '#fca5a5', badgeBg: '#b91c1c', badgeText: '#fff' },
  high:     { bg: 'rgba(220,38,38,0.12)',  border: 'rgba(220,38,38,0.35)',  text: '#fca5a5', badgeBg: '#dc2626', badgeText: '#fff' },
  medium:   { bg: 'rgba(217,119,6,0.12)',  border: 'rgba(217,119,6,0.35)',  text: '#fcd34d', badgeBg: '#d97706', badgeText: '#fff' },
  low:      { bg: 'rgba(101,163,13,0.1)',  border: 'rgba(101,163,13,0.3)',  text: '#86efac', badgeBg: '#65a30d', badgeText: '#fff' },
  info:     { bg: 'rgba(59,130,246,0.1)',  border: 'rgba(59,130,246,0.3)',  text: '#93c5fd', badgeBg: '#3b82f6', badgeText: '#fff' },
  unknown:  { bg: 'rgba(255,255,255,0.04)', border: 'rgba(255,255,255,0.1)', text: '#8181A2', badgeBg: '#374151', badgeText: '#e5e7eb' },
};

function SevBadge({ severity, large }: { severity: string; large?: boolean }) {
  const s = SEV[severity] ?? SEV.unknown;
  return (
    <span
      style={{
        display: 'inline-block',
        padding: large ? '2px 10px' : '1px 6px',
        borderRadius: 4,
        fontSize: large ? '.72rem' : '.65rem',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '.04em',
        background: s.badgeBg,
        color: s.badgeText,
      }}
    >
      {severity}
    </span>
  );
}

/* ── Pill (dark-mode) ───────────────────────── */
const PILL_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  'multi-agent':    { bg: 'rgba(59,130,246,0.1)',  text: '#93c5fd', border: 'rgba(59,130,246,0.25)'  },
  rag:              { bg: 'rgba(220,38,38,0.1)',   text: '#fca5a5', border: 'rgba(220,38,38,0.25)'   },
  'tool-use':       { bg: 'rgba(99,102,241,0.1)',  text: '#a5b4fc', border: 'rgba(99,102,241,0.25)'  },
  'voice-ai':       { bg: 'rgba(16,185,129,0.1)',  text: '#6ee7b7', border: 'rgba(16,185,129,0.25)'  },
  mcp:              { bg: 'rgba(243,162,22,0.1)',  text: '#fcd34d', border: 'rgba(243,162,22,0.25)'  },
  orchestration:    { bg: 'rgba(168,85,247,0.1)',  text: '#d8b4fe', border: 'rgba(168,85,247,0.25)'  },
  default:          { bg: 'rgba(255,255,255,0.06)', text: '#8181A2', border: 'rgba(255,255,255,0.1)' },
};

function CapPill({ tag }: { tag: string }) {
  const key = tag.toLowerCase().replace(/\s+/g, '-');
  const c = PILL_COLORS[key] ?? PILL_COLORS.default;
  return (
    <span style={{ display: 'inline-block', padding: '3px 10px', borderRadius: 9999, fontSize: '.75rem', fontWeight: 500, background: c.bg, color: c.text, border: `1px solid ${c.border}`, whiteSpace: 'nowrap' }}>
      {tag}
    </span>
  );
}

/* ── Risk signal row ────────────────────── */
function RiskSignalRow({ risk }: { risk: RiskIndicator }) {
  const s = SEV[risk.severity] ?? SEV.unknown;
  return (
    <div style={{ display: 'block', padding: '8px 12px', borderRadius: 4, fontSize: '.82rem', fontWeight: 500, lineHeight: 1.5, background: s.bg, color: s.text, border: `1px solid ${s.border}`, wordBreak: 'break-word', marginBottom: 6 }}>
      <span style={{ display: 'inline-block', padding: '1px 6px', marginRight: 8, borderRadius: 3, fontSize: '.65rem', fontWeight: 700, letterSpacing: '.04em', textTransform: 'uppercase', background: 'rgba(0,0,0,.12)', color: 'inherit', verticalAlign: '1px' }}>
        {risk.severity}
      </span>
      {risk.signal}
      {risk.recommended_controls.length > 0 && (
        <div style={{ fontSize: '.73rem', marginTop: 4, opacity: .7 }}>
          Controls: {risk.recommended_controls.join(' · ')}
        </div>
      )}
      {risk.threat_id && (
        <div style={{ fontSize: '.68rem', marginTop: 2, opacity: .55, fontStyle: 'italic' }}>{risk.threat_id}</div>
      )}
    </div>
  );
}

/* ── Vuln card (dark-mode) ──────────────── */
const VULN_LEFT: Record<string, string> = { critical: '#b91c1c', high: '#dc2626', medium: '#d97706', low: '#65a30d' };

function VulnCard({ vuln }: { vuln: Vulnerability }) {
  const sev = vuln.severity.toLowerCase();
  const s = SEV[sev] ?? SEV.unknown;
  return (
    <div style={{ border: `1px solid ${s.border}`, borderLeft: `4px solid ${VULN_LEFT[sev] ?? T.muted}`, borderRadius: 8, padding: '12px 14px', marginBottom: 10, background: s.bg }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
        <SevBadge severity={vuln.severity} large />
        {vuln.cve_id && <span style={{ fontFamily: 'Fira Code, monospace', fontWeight: 700, fontSize: '.85rem', color: T.text }}>{vuln.cve_id}</span>}
        {vuln.cvss_score !== null && <span style={{ fontSize: '.75rem', color: T.muted, fontFamily: 'Fira Code, monospace' }}>CVSS {vuln.cvss_score?.toFixed(1)}</span>}
        {vuln.published && <span style={{ fontSize: '.72rem', color: T.muted }}>{vuln.published.slice(0, 10)}</span>}
        {vuln.source_url && (
          <a href={vuln.source_url} target="_blank" rel="noopener noreferrer" style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4, fontSize: '.75rem', color: T.muted, textDecoration: 'underline' }}>
            Advisory <ExternalLink size={11} />
          </a>
        )}
      </div>
      <p style={{ fontSize: '.85rem', color: s.text, lineHeight: 1.5, wordBreak: 'break-word' }}>{vuln.summary}</p>
      {vuln.affected_versions && (
        <p style={{ fontSize: '.72rem', color: T.muted, marginTop: 6, fontFamily: 'Fira Code, monospace' }}>Affected: {vuln.affected_versions}</p>
      )}
    </div>
  );
}

/* ── Agent card ─────────────────────────── */
function AgentCard({ agent }: { agent: AgentProfile }) {
  const [open, setOpen] = useState(false);
  const typeColors: Record<string, string> = { supervisor: '#6366f1', worker: '#22c55e', utility: '#f59e0b', unknown: '#9ca3af' };
  const tc = typeColors[agent.agent_type] ?? typeColors.unknown;
  return (
    <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8, transition: 'box-shadow 150ms' }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{ width: '100%', display: 'flex', alignItems: 'flex-start', gap: 12, padding: '16px 20px', textAlign: 'left', cursor: 'pointer', background: 'none', border: 'none' }}
      >
        <div style={{ flexShrink: 0, width: 32, height: 32, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', background: `${tc}18`, border: `1px solid ${tc}40` }}>
          <Bot size={15} style={{ color: tc }} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontWeight: 700, fontSize: '1rem', color: T.text }}>{agent.name || 'Unnamed Agent'}</span>
            <span style={{ fontSize: '.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.04em', padding: '2px 8px', borderRadius: 9999, background: `${tc}18`, color: tc, border: `1px solid ${tc}40` }}>
              {agent.agent_type}
            </span>
            {agent.risk_signals[0] && <SevBadge severity={agent.risk_signals[0].severity} />}
          </div>
          <p style={{ fontSize: '.85rem', color: T.muted, marginTop: 4, lineHeight: 1.6 }}>
            {agent.goal || 'No goal description'}
          </p>
        </div>
        <span style={{ color: T.muted, flexShrink: 0 }}>
          {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </span>
      </button>

      {open && (
        <div style={{ padding: '0 20px 16px', borderTop: `1px solid #f3f4f6`, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {agent.source_file && (
            <p style={{ fontSize: '.75rem', fontFamily: 'Fira Code, monospace', color: T.muted, paddingTop: 12, wordBreak: 'break-all' }}>
              {agent.source_file}
            </p>
          )}

          {agent.capabilities.length > 0 && (
            <div>
              <div style={{ fontSize: '.72rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.04em', color: T.muted, marginBottom: 6 }}>Capabilities</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {agent.capabilities.map((cap) => <CapPill key={cap} tag={cap} />)}
              </div>
            </div>
          )}

          {agent.tools.length > 0 && (
            <div>
              <div style={{ fontSize: '.72rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.04em', color: T.muted, marginBottom: 6 }}>Tools</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {agent.tools.map((tool) => (
                  <span key={tool} style={{ fontSize: '.75rem', padding: '2px 8px', borderRadius: 4, fontFamily: 'Fira Code, monospace', background: '#eef2ff', color: '#3730a3', border: '1px solid #c7d2fe' }}>{tool}</span>
                ))}
              </div>
            </div>
          )}

          {agent.risk_signals.length > 0 && (
            <div>
              <div style={{ fontSize: '.72rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.04em', color: T.muted, marginBottom: 6 }}>Risk Signals</div>
              {agent.risk_signals.map((r, i) => <RiskSignalRow key={i} risk={r} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Tab types ──────────────────────────── */
type Tab = 'agents' | 'risks' | 'vulns' | 'tools' | 'mcp' | 'models';

/* ── Tool row ───────────────────────────── */
function ToolRow({ t }: { t: ToolUsage }) {
  return (
    <tr>
      <td style={{ fontFamily: 'Fira Code, monospace', fontWeight: 600, fontSize: '.82rem', maxWidth: 200 }}>{t.tool_name}</td>
      <td><span style={{ fontSize: '.72rem', padding: '2px 7px', borderRadius: 4, background: '#eef2ff', color: '#3730a3', border: '1px solid #c7d2fe', fontFamily: 'Fira Code, monospace' }}>{t.tool_type.replace('_', ' ')}</span></td>
      <td style={{ fontFamily: 'Fira Code, monospace', fontSize: '.75rem', color: T.muted }}>{t.source_file ?? '—'}</td>
    </tr>
  );
}

/* ── MCP row ─────────────────────────────── */
function McpRow({ s }: { s: MCPServer }) {
  return (
    <tr>
      <td style={{ fontWeight: 600, fontSize: '.85rem' }}>{s.name}</td>
      <td><span style={{ fontSize: '.72rem', padding: '2px 7px', borderRadius: 4, background: '#ecfdf5', color: '#065f46', border: '1px solid #a7f3d0', fontFamily: 'Fira Code, monospace' }}>{s.transport}</span></td>
      <td style={{ fontFamily: 'Fira Code, monospace', fontSize: '.75rem', color: T.muted }}>{s.source_file ?? '—'}</td>
    </tr>
  );
}

/* ── Model row ──────────────────────────── */
function ModelRow({ m }: { m: ModelUsage }) {
  return (
    <tr>
      <td style={{ fontFamily: 'Fira Code, monospace', fontWeight: 600, fontSize: '.82rem' }}>{m.model_name}</td>
      <td style={{ fontSize: '.82rem', color: T.muted }}>{m.provider}</td>
      <td style={{ fontSize: '.82rem', color: T.muted }}>{m.role}</td>
      <td><span style={{ fontSize: '.72rem', padding: '2px 7px', borderRadius: 4, background: 'rgba(255,255,255,0.06)', color: T.muted, border: `1px solid ${T.border}`, fontFamily: 'Fira Code, monospace' }}>{m.source}</span></td>
    </tr>
  );
}

/* ── Table wrapper ──────────────────────── */
function DataTable({ headers, children, empty }: { headers: string[]; children: React.ReactNode; empty?: boolean }) {
  if (empty) return <p style={{ textAlign: 'center', padding: '48px 20px', color: T.muted, fontSize: '.9rem', fontStyle: 'italic' }}>Nothing to show.</p>;
  return (
    <div style={{ overflowX: 'auto', border: `1px solid ${T.border}`, borderRadius: 8, background: T.surface }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '.82rem' }}>
        <thead style={{ background: T.surfaceHi }}>
          <tr>
            {headers.map((h) => (
              <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600, color: T.muted, fontSize: '.75rem', textTransform: 'uppercase', letterSpacing: '.04em', borderBottom: `1px solid ${T.border}`, whiteSpace: 'nowrap' }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

/* ── Main Results page ──────────────────── */
export default function Results() {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<Tab>('agents');

  useEffect(() => {
    if (!jobId) return;
    pollJob(jobId)
      .then((job) => {
        if (job.status === 'done' && job.result) {
          setReport(job.result);
        } else if (job.status === 'error') {
          setError(job.error ?? 'Unknown error');
        } else {
          navigate(`/scanning/${jobId}`);
        }
      })
      .catch(() => setError('Failed to load results'))
      .finally(() => setLoading(false));
  }, [jobId, navigate]);

  if (loading) return (
    <main style={{ minHeight: '100dvh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: T.bg }}>
      <div className="spin-slow" style={{ width: 32, height: 32, borderRadius: '50%', border: `2px solid ${T.border}`, borderTopColor: T.quin, display: 'inline-block' }} />
    </main>
  );

  if (error || !report) return (
    <main style={{ minHeight: '100dvh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16, background: T.bg }}>
      <p style={{ color: T.high }}>{error || 'No results found'}</p>
      <button onClick={() => navigate('/')} style={{ color: T.quin, textDecoration: 'underline', cursor: 'pointer', background: 'none', border: 'none', fontSize: '.9rem' }}>
        Back to search
      </button>
    </main>
  );

  const allRisks = [...report.risk_signals, ...report.agents.flatMap((a) => a.risk_signals)];
  const criticalCount = allRisks.filter((r) => r.severity === 'critical').length;
  const highCount     = allRisks.filter((r) => r.severity === 'high').length;
  const repoName      = report.repo_path.split('/').pop() ?? report.repo_path;
  const scanTime      = new Date(report.scan_timestamp).toLocaleString();
  const totalRisks    = report.risk_signals.length + report.agents.reduce((a, ag) => a + ag.risk_signals.length, 0);

  const TABS: { key: Tab; label: string; count: number }[] = [
    { key: 'agents', label: 'AI Agents',   count: report.agents.length },
    { key: 'risks',  label: 'Risk Signals', count: totalRisks },
    { key: 'vulns',  label: 'Vulnerabilities', count: report.vulnerabilities.length },
    { key: 'tools',  label: 'Tools',        count: report.tool_usages.length },
    { key: 'mcp',    label: 'MCP Servers',  count: report.mcp_servers.length },
    { key: 'models', label: 'Models',       count: report.model_usages.length },
  ];

  const heroStats = [
    { label: 'Agents detected',   value: report.agents.length,      icon: <Bot size={18} />, accent: report.agents.length > 0 ? T.quin : T.muted },
    { label: 'Risk signals',      value: totalRisks,                 icon: <Shield size={18} />, accent: criticalCount > 0 ? T.high : highCount > 0 ? T.medium : T.muted },
    { label: 'Known CVEs',        value: report.vulnerabilities.length, icon: <AlertTriangle size={18} />, accent: report.vulnerabilities.length > 0 ? T.high : T.muted },
    { label: 'Confidence',        value: `${Math.round(report.confidence * 100)}%`, icon: <CheckCircle size={18} />, accent: report.confidence > 0.8 ? T.low : T.medium },
  ];

  return (
    <main style={{ minHeight: '100dvh', display: 'flex', flexDirection: 'column', background: T.bg, fontFamily: 'Fira Sans, system-ui, sans-serif', color: T.text }}>

      {/* ── Dark header ── */}
      <header style={{ background: HEADER_BG, position: 'relative', overflow: 'hidden' }}>
        {/* Cream radial accent */}
        <div aria-hidden style={{ position: 'absolute', inset: 0, background: 'radial-gradient(circle at 8% 20%,rgba(245,230,211,.08) 0%,transparent 50%)', pointerEvents: 'none' }} />
        {/* Bottom accent line */}
        <div aria-hidden style={{ position: 'absolute', left: 0, right: 0, bottom: 0, height: 2, background: `linear-gradient(90deg,transparent 0%,${T.quin} 30%,${T.quin} 70%,transparent 100%)`, opacity: .75 }} />

        <div style={{ maxWidth: 1120, margin: '0 auto', padding: '24px 24px 22px', position: 'relative' }}>
          {/* Top nav row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
            <button
              onClick={() => navigate('/')}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '.82rem', color: 'rgba(253,246,236,0.6)', background: 'none', border: 'none', cursor: 'pointer', transition: 'color 150ms' }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = T.cream)}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'rgba(253,246,236,0.6)')}
            >
              <ArrowLeft size={14} /> New scan
            </button>
            <div style={{ flex: 1 }} />
            <span style={{ fontSize: '.72rem', fontFamily: 'Fira Code, monospace', color: 'rgba(253,246,236,0.45)', letterSpacing: '.02em' }}>{scanTime}</span>
          </div>

          {/* Brand + title */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
            <div>
              <div style={{ fontSize: '1.32rem', fontWeight: 700, letterSpacing: '-.025em', color: T.cream, lineHeight: 1.1 }}>
                Quin <span style={{ color: T.quin }}>Scanner</span>
              </div>
              <div style={{ fontSize: '.7rem', fontWeight: 600, color: 'rgba(253,246,236,0.55)', letterSpacing: '.12em', textTransform: 'uppercase', marginTop: 4 }}>
                AI Agent Security &amp; Risk Report
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontWeight: 600, color: T.cream, fontSize: '.88rem', fontFamily: 'Fira Code, monospace', wordBreak: 'break-all' }}>
                {repoName}
              </div>
              <div style={{ fontSize: '.78rem', color: 'rgba(253,246,236,0.55)', marginTop: 3 }}>
                {report.framework !== 'unknown' ? report.framework : 'AI application'} ·{' '}
                {report.is_ai_application ? 'AI detected' : 'No agents'}
              </div>
            </div>
          </div>

          {/* Hero stat cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(200px,1fr))', gap: 12, marginTop: 20 }}>
            {heroStats.map(({ label, value, icon, accent }) => (
              <div key={label} style={{ background: T.surface, border: `1px solid ${T.border}`, borderLeft: `4px solid ${accent}`, borderRadius: 12, padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
                <span style={{ color: accent }}>{icon}</span>
                <div>
                  <div style={{ fontSize: '1.35rem', fontWeight: 700, letterSpacing: '-.02em', color: T.text }}>{value}</div>
                  <div style={{ fontSize: '.8rem', color: T.muted, fontWeight: 500 }}>{label}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </header>

      {/* ── Light body ── */}
      <div style={{ maxWidth: 1120, margin: '0 auto', padding: '24px 24px 64px', width: '100%', flex: 1 }}>

        {/* Capability pills */}
        {report.capability_tags.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
            {report.capability_tags.map((tag) => <CapPill key={tag} tag={tag} />)}
          </div>
        )}

        {/* Summary */}
        {report.summary && (
          <div style={{ marginBottom: 16, padding: '14px 18px', background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8, fontSize: '.9rem', lineHeight: 1.7, color: '#404040' }}>
            {report.summary}
          </div>
        )}

        {/* Critical/high alert */}
        {(criticalCount > 0 || highCount > 0) && (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '12px 16px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 8, marginBottom: 16, fontSize: '.88rem', color: '#991b1b' }}>
            <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: 2 }} />
            <p>
              {criticalCount > 0 && <><strong>{criticalCount} critical</strong>{' '}</>}
              {highCount > 0 && <><strong>{highCount} high</strong>{' '}</>}
              severity risk{(criticalCount + highCount) !== 1 ? 's' : ''} detected. Review before deployment.
            </p>
          </div>
        )}

        {/* Repo-level risk signals (always visible above tabs) */}
        {report.risk_signals.length > 0 && (
          <div style={{ marginBottom: 20 }}>
            <h3 style={{ fontSize: '.82rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.04em', color: T.muted, marginBottom: 10 }}>
              Cross-Cutting Risks
            </h3>
            {report.risk_signals.map((r, i) => <RiskSignalRow key={i} risk={r} />)}
          </div>
        )}

        {/* Vulnerabilities (always visible) */}
        {report.vulnerabilities.length > 0 && (
          <div style={{ marginBottom: 20 }}>
            <h3 style={{ fontSize: '.82rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.04em', color: T.muted, marginBottom: 10 }}>
              Known Vulnerabilities
            </h3>
            {report.vulnerabilities.map((v, i) => <VulnCard key={i} vuln={v} />)}
          </div>
        )}

        {/* Tab bar */}
        <div style={{ display: 'flex', gap: 0, borderBottom: `1px solid ${T.border}`, marginTop: 8, overflowX: 'auto' }}>
          {TABS.map(({ key, label, count }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              style={{
                padding: '10px 18px',
                fontSize: '.82rem',
                fontWeight: activeTab === key ? 600 : 500,
                color: activeTab === key ? T.primary : T.muted,
                background: 'none',
                border: 'none',
                borderBottom: activeTab === key ? `2px solid ${T.primary}` : '2px solid transparent',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'color 150ms, border-color 150ms',
                marginBottom: -1,
              }}
            >
              {label}
              {count > 0 && (
                <span style={{ marginLeft: 6, fontSize: '.72rem', padding: '1px 6px', borderRadius: 9999, background: activeTab === key ? `${T.primary}18` : 'rgba(255,255,255,0.06)', color: activeTab === key ? T.primary : T.muted }}>
                  {count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab panels */}
        <div style={{ marginTop: 20 }}>

          {activeTab === 'agents' && (
            report.agents.length === 0
              ? <p style={{ textAlign: 'center', padding: '48px 20px', color: T.muted, fontStyle: 'italic' }}>No AI agents detected.</p>
              : <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(480px,1fr))', gap: 16 }}>
                  {report.agents.map((agent, i) => <AgentCard key={i} agent={agent} />)}
                </div>
          )}

          {activeTab === 'risks' && (
            totalRisks === 0
              ? <p style={{ textAlign: 'center', padding: '48px 20px', color: T.muted, fontStyle: 'italic' }}>No risk signals found.</p>
              : <>
                  {report.agents.filter((a) => a.risk_signals.length > 0).map((agent, i) => (
                    <div key={i} style={{ marginBottom: 20 }}>
                      <h4 style={{ fontSize: '.82rem', fontWeight: 700, color: T.muted, textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 8 }}>
                        {agent.name || 'Unnamed Agent'}
                      </h4>
                      {agent.risk_signals.map((r, j) => <RiskSignalRow key={j} risk={r} />)}
                    </div>
                  ))}
                </>
          )}

          {activeTab === 'vulns' && (
            report.vulnerabilities.length === 0
              ? <p style={{ textAlign: 'center', padding: '48px 20px', color: T.muted, fontStyle: 'italic' }}>No known CVEs found.</p>
              : report.vulnerabilities.map((v, i) => <VulnCard key={i} vuln={v} />)
          )}

          {activeTab === 'tools' && (
            <DataTable headers={['Tool Name', 'Type', 'Source File']} empty={report.tool_usages.length === 0}>
              {report.tool_usages.map((t, i) => <ToolRow key={i} t={t} />)}
            </DataTable>
          )}

          {activeTab === 'mcp' && (
            <DataTable headers={['Server Name', 'Transport', 'Source File']} empty={report.mcp_servers.length === 0}>
              {report.mcp_servers.map((s, i) => <McpRow key={i} s={s} />)}
            </DataTable>
          )}

          {activeTab === 'models' && (
            <DataTable headers={['Model', 'Provider', 'Role', 'Source']} empty={report.model_usages.length === 0}>
              {report.model_usages.map((m, i) => <ModelRow key={i} m={m} />)}
            </DataTable>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer style={{ borderTop: `1px solid ${T.border}`, padding: '20px 0', textAlign: 'center', fontSize: '.78rem', color: T.muted }}>
        Quin Agent Scanner ·{' '}
        <a href="https://gaincontrol.ai" target="_blank" rel="noopener noreferrer" style={{ color: T.muted, textDecoration: 'underline' }}>
          gaincontrol.ai
        </a>
      </footer>
    </main>
  );
}
