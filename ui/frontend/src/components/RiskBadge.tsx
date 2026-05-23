const SEVERITY_STYLES: Record<string, { bg: string; border: string; text: string; label: string }> = {
  critical: { bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.35)',  text: '#ef4444', label: 'Critical' },
  high:     { bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.35)', text: '#f97316', label: 'High'     },
  medium:   { bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.35)', text: '#f59e0b', label: 'Medium'   },
  low:      { bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.35)',  text: '#22c55e', label: 'Low'      },
  info:     { bg: 'rgba(99,102,241,0.12)', border: 'rgba(99,102,241,0.35)', text: '#6366f1', label: 'Info'     },
  unknown:  { bg: 'rgba(255,255,255,0.06)', border: 'rgba(255,255,255,0.1)', text: 'rgba(248,250,252,0.5)', label: 'Unknown' },
};

interface Props {
  severity: string;
  size?: 'sm' | 'md';
}

export default function RiskBadge({ severity, size = 'sm' }: Props) {
  const s = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.unknown;
  return (
    <span
      className={`inline-flex items-center rounded-full font-semibold tracking-wide uppercase ${size === 'sm' ? 'text-[10px] px-2 py-0.5' : 'text-xs px-3 py-1'}`}
      style={{ background: s.bg, border: `1px solid ${s.border}`, color: s.text }}
    >
      {s.label}
    </span>
  );
}
