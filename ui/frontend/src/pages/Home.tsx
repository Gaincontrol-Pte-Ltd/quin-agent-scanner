import { useState, useRef, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ChevronDown, ChevronUp, GitBranch, FolderOpen, Zap } from 'lucide-react';
import { startScan, pollJob } from '../api';

/* ── Design tokens — gaincontrol.ai/quin theme ───── */
const C = {
  bg:           '#0B0F1E',          // hsl(252,47%,8%)
  card:         '#12172B',          // hsl(252,40%,12%)
  border:       '#24293D',          // hsl(252,25%,19%)
  text:         '#EAEAF1',          // hsl(240,20%,93%)
  textMuted:    '#8181A2',          // hsl(240,15%,57%)
  quin:         '#F3A216',          // hsl(38,90%,52%) — Quin amber
  quinDim:      'rgba(243,162,22,0.1)',
  quinBorder:   'rgba(243,162,22,0.22)',
  quinGlow:     '0 0 48px rgba(243,162,22,0.15)',
  primary:      '#875BF1',          // hsl(258,84%,65%) — purple
  primaryDim:   'rgba(135,91,241,0.12)',
  primaryBorder:'rgba(135,91,241,0.25)',
  glass:        'rgba(18,23,43,0.65)',
  glassBorder:  'rgba(234,234,241,0.08)',
};

const BG = `radial-gradient(ellipse 80% 60% at 50% -10%, rgba(135,91,241,0.15) 0%, transparent 60%), linear-gradient(160deg, #0B0F1E 0%, #0e1228 55%, #100d1f 100%)`;

const EXAMPLES = [
  'anthropics/anthropic-sdk-python',
  'langchain-ai/langchain',
  'openai/openai-python',
  'microsoft/autogen',
];

const BADGES = ['multi-agent', 'RAG', 'tool-use', 'voice-ai', 'MCP', 'orchestration'];

const STEPS = [
  'Cloning repository…',
  'Indexing files…',
  'Detecting AI frameworks…',
  'Extracting system prompts…',
  'Identifying models…',
  'Analysing agent intent…',
  'Checking vulnerabilities…',
  'Mapping risk indicators…',
  'Generating report…',
];

/* ── Floating particle ───────────────────────────── */
function Particle({ x, y, delay, size }: { x: number; y: number; delay: number; size: number }) {
  return (
    <div aria-hidden style={{
      position: 'absolute',
      left: `${x}%`, top: `${y}%`,
      width: size, height: size,
      borderRadius: '50%',
      background: C.quin,
      opacity: 0,
      animation: `particle-rise ${3 + Math.random() * 3}s ease-out ${delay}s infinite`,
    }} />
  );
}

/* ── Capability floating badge ───────────────────── */
function FloatingBadge({ label, delay }: { label: string; delay: number }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '4px 12px', borderRadius: 9999,
      fontSize: '0.72rem', fontWeight: 600,
      fontFamily: 'Fira Code, monospace',
      color: C.textMuted,
      background: C.glass,
      backdropFilter: 'blur(12px)', WebkitBackdropFilter: 'blur(12px)',
      border: `1px solid ${C.glassBorder}`,
      animation: `sphere-float ${4 + delay * 0.7}s ease-in-out ${delay * 0.3}s infinite`,
    }}>
      {label}
    </span>
  );
}

/* ── Compact scan progress panel ─────────────────── */
function ScanPanel({
  stepIdx, jobId, error, onDismiss,
}: {
  stepIdx: number; jobId: string; error: string; onDismiss: () => void;
}) {
  const progress = Math.round(((stepIdx + 1) / STEPS.length) * 100);

  return (
    <div className="fade-up" style={{
      marginTop: 12,
      padding: '20px 24px',
      borderRadius: 16,
      background: C.glass,
      backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)',
      border: `1px solid ${error ? 'rgba(239,68,68,0.3)' : C.quinBorder}`,
      display: 'flex', flexDirection: 'column', gap: 14,
    }}>
      {error ? (
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
          <div>
            <p style={{ fontSize: '0.9rem', fontWeight: 600, color: '#ef4444' }}>Scan failed</p>
            <p style={{ fontSize: '0.82rem', color: C.textMuted, marginTop: 4 }}>{error}</p>
          </div>
          <button
            onClick={onDismiss}
            style={{ fontSize: '0.75rem', color: C.quin, background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline', flexShrink: 0 }}
          >
            Dismiss
          </button>
        </div>
      ) : (
        <>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="spin-slow" style={{
                display: 'inline-block', flexShrink: 0,
                width: 14, height: 14, borderRadius: '50%',
                border: `2px solid ${C.quinBorder}`,
                borderTopColor: C.quin,
              }} />
              <span style={{ fontSize: '0.88rem', fontFamily: 'Fira Code, monospace', color: C.text }}>
                {STEPS[stepIdx]}
              </span>
            </div>
            <span style={{ fontSize: '0.72rem', fontFamily: 'Fira Code, monospace', color: 'rgba(234,234,241,0.25)', flexShrink: 0 }}>
              {jobId.slice(0, 8)}…
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div style={{ width: '100%', height: 3, borderRadius: 9999, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
              <div style={{
                height: '100%', borderRadius: 9999,
                width: `${progress}%`,
                background: `linear-gradient(90deg, ${C.quin}, ${C.primary})`,
                transition: 'width 0.7s ease-out',
              }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', fontFamily: 'Fira Code, monospace', color: 'rgba(234,234,241,0.2)' }}>
              <span>Step {stepIdx + 1}/{STEPS.length}</span>
              <span>{progress}%</span>
            </div>
          </div>

          {/* Step dots */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
            {STEPS.map((step, i) => (
              <div key={step} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{
                  width: i === stepIdx ? 8 : 6,
                  height: i === stepIdx ? 8 : 6,
                  borderRadius: '50%', flexShrink: 0,
                  transition: 'all 0.3s',
                  background:
                    i < stepIdx  ? 'rgba(34,197,94,0.6)' :
                    i === stepIdx ? C.quin :
                    'rgba(255,255,255,0.1)',
                  boxShadow: i === stepIdx ? `0 0 8px ${C.quin}` : 'none',
                }} title={step} />
                {i < STEPS.length - 1 && (
                  <div style={{ width: 16, height: 1, background: i < stepIdx ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.06)' }} />
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/* ── Main Home page ──────────────────────────────── */
export default function Home() {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);

  const [target, setTarget]           = useState('');
  const [showOptions, setShowOptions] = useState(false);
  const [noLlm, setNoLlm]             = useState(true);
  const [noVulnCheck, setNoVulnCheck] = useState(false);
  const [llmProvider, setLlmProvider] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [branch, setBranch]           = useState('main');
  const [loading, setLoading]         = useState(false);
  const [startError, setStartError]   = useState('');
  const [focused, setFocused]         = useState(false);

  const [scanJobId, setScanJobId]     = useState('');
  const [scanError, setScanError]     = useState('');
  const [stepIdx, setStepIdx]         = useState(0);

  const particles = useRef(
    Array.from({ length: 24 }, (_, i) => ({
      x: Math.random() * 100,
      y: 20 + Math.random() * 70,
      delay: i * 0.45,
      size: 1.5 + Math.random() * 2,
    }))
  );

  const stepRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearTimers = () => {
    if (stepRef.current) { clearInterval(stepRef.current); stepRef.current = null; }
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  useEffect(() => {
    if (!scanJobId) return;
    setStepIdx(0);
    stepRef.current = setInterval(() => {
      setStepIdx((i) => (i < STEPS.length - 1 ? i + 1 : i));
    }, 2800);
    pollRef.current = setInterval(async () => {
      try {
        const job = await pollJob(scanJobId);
        if (job.status === 'done') {
          clearTimers();
          navigate(`/results/${scanJobId}`);
        } else if (job.status === 'error') {
          clearTimers();
          setScanError(job.error ?? 'Unknown error');
        }
      } catch { /* keep polling */ }
    }, 1500);
    return clearTimers;
  }, [scanJobId, navigate]);

  const handleScan = useCallback(async () => {
    const t = target.trim();
    if (!t) { inputRef.current?.focus(); return; }
    setStartError('');
    setScanError('');
    setLoading(true);
    try {
      const { job_id } = await startScan({
        target: t, no_llm: noLlm, no_vuln_check: noVulnCheck,
        llm_provider: llmProvider || undefined,
        github_token: githubToken || undefined,
        branch: branch || 'main',
      });
      setShowOptions(false);
      setScanJobId(job_id);
    } catch (err) {
      setStartError(err instanceof Error ? err.message : 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  }, [target, noLlm, noVulnCheck, llmProvider, githubToken, branch]);

  const handleKey = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleScan(); };

  const isScanning = !!scanJobId && !scanError;
  const isLocal    = target.startsWith('.') || target.startsWith('/');
  const isGitHub   = target.includes('github.com') || /^[\w.-]+\/[\w.-]+$/.test(target);

  return (
    <main style={{
      minHeight: '100dvh',
      background: BG,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '40px 24px',
      position: 'relative',
      overflow: 'hidden',
      fontFamily: 'Inter, system-ui, sans-serif',
    }}>

      {/* Particle field */}
      <div aria-hidden style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}>
        {particles.current.map((p, i) => <Particle key={i} {...p} />)}
      </div>

      {/* Ambient blobs */}
      <div aria-hidden style={{
        position: 'absolute', inset: 0, pointerEvents: 'none',
        background: `
          radial-gradient(ellipse 55% 45% at 10% 85%, rgba(243,162,22,0.07) 0%, transparent 60%),
          radial-gradient(ellipse 45% 40% at 90% 15%, rgba(135,91,241,0.09) 0%, transparent 55%)
        `,
      }} />

      {/* Perspective grid floor */}
      <div aria-hidden style={{
        position: 'absolute', bottom: 0, left: 0, right: 0,
        height: 280,
        backgroundImage: `
          linear-gradient(rgba(243,162,22,0.07) 1px, transparent 1px),
          linear-gradient(90deg, rgba(135,91,241,0.05) 1px, transparent 1px)
        `,
        backgroundSize: '60px 60px',
        transform: 'perspective(400px) rotateX(70deg)',
        transformOrigin: 'bottom center',
        maskImage: 'linear-gradient(to top, rgba(0,0,0,0.4) 0%, transparent 100%)',
        WebkitMaskImage: 'linear-gradient(to top, rgba(0,0,0,0.4) 0%, transparent 100%)',
        pointerEvents: 'none',
      }} />

      {/* Content column */}
      <div style={{
        position: 'relative',
        width: '100%',
        maxWidth: 680,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 28,
      }}>

        {/* Capability badges */}
        <div className="fade-up" style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center', maxWidth: 480 }}>
          {BADGES.map((b, i) => <FloatingBadge key={b} label={b} delay={i} />)}
        </div>

        {/* Wordmark */}
        <div className="fade-up delay-100" style={{ textAlign: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'center', gap: 1 }}>
            <span style={{
              fontFamily: 'Fira Code, monospace',
              fontSize: 'clamp(3.5rem, 10vw, 5.5rem)',
              fontWeight: 700,
              letterSpacing: '-0.04em',
              color: C.text,
              lineHeight: 1,
            }}>quin</span>
            <span style={{
              fontFamily: 'Fira Code, monospace',
              fontSize: 'clamp(3.5rem, 10vw, 5.5rem)',
              fontWeight: 700,
              color: C.quin,
              lineHeight: 1,
            }}>.</span>
          </div>
          <p style={{
            marginTop: 8,
            fontSize: '0.7rem',
            fontWeight: 600,
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            color: 'rgba(129,129,162,0.7)',
          }}>AI Agent Scanner · by Gaincontrol</p>
        </div>

        {/* Tagline */}
        <p className="fade-up delay-200" style={{
          textAlign: 'center',
          fontSize: '1rem',
          lineHeight: 1.7,
          color: C.textMuted,
          maxWidth: 440,
        }}>
          Point Quin at any repo — get back every AI agent, its tools, and what risks it carries.
        </p>

        {/* ── Search bar + panels ─────────────────── */}
        <div className="fade-up delay-300" style={{ width: '100%' }}>

          {/* Glassmorphism search bar */}
          <div
            className={!isScanning && focused ? 'glow-pulse' : ''}
            style={{
              position: 'relative',
              display: 'flex',
              alignItems: 'center',
              width: '100%',
              borderRadius: 20,
              background: C.glass,
              backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)',
              border: `1.5px solid ${focused && !isScanning ? C.quinBorder : isScanning ? 'rgba(243,162,22,0.15)' : C.glassBorder}`,
              boxShadow: focused && !isScanning
                ? `0 0 0 4px rgba(243,162,22,0.06), 0 20px 60px rgba(0,0,0,0.5), ${C.quinGlow}`
                : `0 8px 40px rgba(0,0,0,0.4)`,
              opacity: isScanning ? 0.72 : 1,
              transition: 'opacity 0.2s, border-color 0.2s, box-shadow 0.2s',
            } as React.CSSProperties}
          >
            {/* Left icon */}
            <div style={{ paddingLeft: 22, paddingRight: 14, flexShrink: 0, color: focused ? C.quin : C.textMuted, transition: 'color 0.2s' }}>
              {isLocal ? <FolderOpen size={22} /> : isGitHub ? <GitBranch size={22} /> : <Search size={22} />}
            </div>

            {/* Input */}
            <input
              ref={inputRef}
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={handleKey}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              placeholder="owner/repo, GitHub URL, or local path…"
              aria-label="Scan target"
              autoFocus
              autoComplete="off"
              spellCheck={false}
              disabled={isScanning}
              style={{
                flex: 1,
                background: 'transparent',
                border: 'none', outline: 'none',
                padding: '22px 8px',
                fontSize: '1.05rem',
                fontFamily: 'Fira Code, monospace',
                color: C.text,
                caretColor: C.quin,
                cursor: isScanning ? 'not-allowed' : 'text',
              }}
            />

            {/* Scan button */}
            <button
              onClick={isScanning ? undefined : handleScan}
              disabled={loading || isScanning}
              aria-label="Run scan"
              style={{
                margin: '0 10px',
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '12px 24px', borderRadius: 12, border: 'none',
                background: loading || isScanning ? 'rgba(243,162,22,0.5)' : C.quin,
                color: '#0B0F1E',
                fontSize: '0.9rem', fontWeight: 700,
                cursor: loading || isScanning ? 'not-allowed' : 'pointer',
                transition: 'background 0.15s, transform 0.1s',
                flexShrink: 0, letterSpacing: '0.01em',
              }}
              onMouseEnter={e => { if (!loading && !isScanning) (e.currentTarget as HTMLElement).style.background = '#d48d10'; }}
              onMouseLeave={e => { if (!loading && !isScanning) (e.currentTarget as HTMLElement).style.background = C.quin; }}
              onMouseDown={e => { if (!isScanning) (e.currentTarget as HTMLElement).style.transform = 'scale(0.97)'; }}
              onMouseUp={e => { (e.currentTarget as HTMLElement).style.transform = 'scale(1)'; }}
            >
              {loading || isScanning
                ? <span className="spin-slow" style={{ display: 'inline-block', width: 16, height: 16, border: '2px solid rgba(11,15,30,0.3)', borderTopColor: '#0B0F1E', borderRadius: '50%' }} />
                : <Zap size={16} strokeWidth={2.5} />
              }
              {loading ? 'Starting…' : isScanning ? 'Scanning…' : 'Scan'}
            </button>
          </div>

          {/* Start error */}
          {startError && (
            <p style={{ textAlign: 'center', color: '#ef4444', fontSize: '0.85rem', marginTop: 10 }}>{startError}</p>
          )}

          {/* Inline scan progress panel */}
          {(isScanning || scanError) && (
            <ScanPanel
              stepIdx={stepIdx}
              jobId={scanJobId}
              error={scanError}
              onDismiss={() => { setScanJobId(''); setScanError(''); }}
            />
          )}

          {/* Options toggle */}
          {!isScanning && !scanError && (
            <div style={{ display: 'flex', justifyContent: 'center', marginTop: 12 }}>
              <button
                onClick={() => setShowOptions(v => !v)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  background: 'none', border: 'none',
                  color: 'rgba(129,129,162,0.5)',
                  fontSize: '0.78rem', cursor: 'pointer',
                  transition: 'color 0.15s',
                }}
                onMouseEnter={e => ((e.currentTarget as HTMLElement).style.color = C.textMuted)}
                onMouseLeave={e => ((e.currentTarget as HTMLElement).style.color = 'rgba(129,129,162,0.5)')}
              >
                {showOptions ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                {showOptions ? 'Hide options' : 'Scan options'}
              </button>
            </div>
          )}

          {/* Options panel */}
          {showOptions && !isScanning && (
            <div className="fade-up" style={{
              marginTop: 12, padding: '20px 24px', borderRadius: 16,
              background: C.glass,
              backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)',
              border: `1px solid ${C.glassBorder}`,
              display: 'flex', flexDirection: 'column', gap: 16,
            }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px 32px' }}>
                {([
                  [noLlm,       setNoLlm,       'Skip LLM analysis', '(no API key needed)'],
                  [noVulnCheck, setNoVulnCheck, 'Skip vuln check',   ''],
                ] as const).map(([val, set, label, hint]) => (
                  <label key={label} style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', userSelect: 'none' }}>
                    <input
                      type="checkbox"
                      checked={val as boolean}
                      onChange={e => (set as (v: boolean) => void)(e.target.checked)}
                      style={{ width: 16, height: 16, accentColor: C.quin, cursor: 'pointer' }}
                    />
                    <span style={{ fontSize: '0.85rem', color: C.textMuted }}>
                      {label}
                      {hint && <span style={{ marginLeft: 4, fontSize: '0.7rem', color: 'rgba(129,129,162,0.5)' }}>{hint}</span>}
                    </span>
                  </label>
                ))}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={{ fontSize: '0.72rem', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'rgba(129,129,162,0.6)' }}>LLM Provider</label>
                  <select
                    value={llmProvider}
                    onChange={e => setLlmProvider(e.target.value)}
                    style={{
                      background: 'rgba(18,23,43,0.8)', border: `1px solid ${C.border}`,
                      borderRadius: 10, padding: '9px 12px', color: C.text,
                      fontSize: '0.85rem', outline: 'none', cursor: 'pointer',
                    }}
                  >
                    <option value="">Auto-detect</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="openai">OpenAI</option>
                    <option value="google">Google</option>
                    <option value="ollama">Ollama (local)</option>
                  </select>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={{ fontSize: '0.72rem', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'rgba(129,129,162,0.6)' }}>Branch</label>
                  <input
                    type="text"
                    value={branch}
                    onChange={e => setBranch(e.target.value)}
                    placeholder="main"
                    style={{
                      background: 'rgba(18,23,43,0.8)', border: `1px solid ${C.border}`,
                      borderRadius: 10, padding: '9px 12px', color: C.text,
                      fontSize: '0.85rem', outline: 'none',
                      fontFamily: 'Fira Code, monospace',
                    }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={{ fontSize: '0.72rem', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'rgba(129,129,162,0.6)' }}>
                  GitHub Token <span style={{ textTransform: 'none', fontSize: '0.7rem', opacity: 0.6 }}>(optional)</span>
                </label>
                <input
                  type="password"
                  value={githubToken}
                  onChange={e => setGithubToken(e.target.value)}
                  placeholder="ghp_…"
                  style={{
                    background: 'rgba(18,23,43,0.8)', border: `1px solid ${C.border}`,
                    borderRadius: 10, padding: '9px 12px', color: C.text,
                    fontSize: '0.85rem', outline: 'none',
                    fontFamily: 'Fira Code, monospace',
                  }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Example chips */}
        {!isScanning && !scanError && (
          <div className="fade-up delay-400" style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 8 }}>
            {EXAMPLES.map(ex => (
              <button
                key={ex}
                onClick={() => setTarget(ex)}
                style={{
                  padding: '6px 14px', borderRadius: 9999,
                  background: 'rgba(18,23,43,0.6)',
                  backdropFilter: 'blur(8px)', WebkitBackdropFilter: 'blur(8px)',
                  border: `1px solid ${C.border}`,
                  color: C.textMuted,
                  fontSize: '0.75rem', fontFamily: 'Fira Code, monospace',
                  cursor: 'pointer', transition: 'all 0.15s ease',
                }}
                onMouseEnter={e => {
                  const el = e.currentTarget as HTMLElement;
                  el.style.borderColor = C.quinBorder;
                  el.style.color = C.text;
                  el.style.background = C.quinDim;
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget as HTMLElement;
                  el.style.borderColor = C.border;
                  el.style.color = C.textMuted;
                  el.style.background = 'rgba(18,23,43,0.6)';
                }}
              >
                {ex}
              </button>
            ))}
          </div>
        )}

        {/* Footer */}
        <div className="fade-up delay-500" style={{ display: 'flex', gap: 24, fontSize: '0.75rem', color: 'rgba(129,129,162,0.4)' }}>
          {[
            ['gaincontrol.ai', 'https://gaincontrol.ai/quin'],
            ['GitHub', 'https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner'],
            ['Report issue', 'https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/issues'],
          ].map(([label, href]) => (
            <a key={label} href={href} target="_blank" rel="noopener noreferrer"
              style={{ color: 'inherit', textDecoration: 'none', transition: 'color 0.15s' }}
              onMouseEnter={e => ((e.currentTarget as HTMLElement).style.color = C.textMuted)}
              onMouseLeave={e => ((e.currentTarget as HTMLElement).style.color = 'rgba(129,129,162,0.4)')}
            >{label}</a>
          ))}
        </div>
      </div>
    </main>
  );
}
