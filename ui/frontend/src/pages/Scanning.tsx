import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { pollJob } from '../api';
import type { JobStatus } from '../types';

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

export default function Scanning() {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const [status, setStatus] = useState<JobStatus['status']>('pending');
  const [stepIdx, setStepIdx] = useState(0);
  const [error, setError] = useState('');
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const stepIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Cycle through fake steps for UX while backend works
  useEffect(() => {
    stepIntervalRef.current = setInterval(() => {
      setStepIdx((i) => (i < STEPS.length - 1 ? i + 1 : i));
    }, 2800);
    return () => { if (stepIntervalRef.current) clearInterval(stepIntervalRef.current); };
  }, []);

  // Poll for job completion
  useEffect(() => {
    if (!jobId) return;
    intervalRef.current = setInterval(async () => {
      try {
        const job = await pollJob(jobId);
        setStatus(job.status);
        if (job.status === 'done') {
          if (intervalRef.current) clearInterval(intervalRef.current);
          if (stepIntervalRef.current) clearInterval(stepIntervalRef.current);
          navigate(`/results/${jobId}`);
        } else if (job.status === 'error') {
          if (intervalRef.current) clearInterval(intervalRef.current);
          if (stepIntervalRef.current) clearInterval(stepIntervalRef.current);
          setError(job.error ?? 'Unknown error');
        }
      } catch {
        // keep polling
      }
    }, 1500);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [jobId, navigate]);

  const progress = Math.round(((stepIdx + 1) / STEPS.length) * 100);

  return (
    <main className="flex flex-col items-center justify-center min-h-dvh px-4 relative overflow-hidden">
      {/* Background glow */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(ellipse 50% 50% at 50% 50%, rgba(226,94,71,0.06) 0%, transparent 70%)',
        }}
      />

      <div className="relative flex flex-col items-center gap-10 w-full max-w-md">
        {/* Animated scanning ring */}
        <div className="relative flex items-center justify-center" style={{ width: 140, height: 140 }}>
          {/* Outer ring */}
          <div
            className="absolute inset-0 rounded-full spin-slow"
            style={{
              border: '2px solid transparent',
              borderTopColor: '#e25e47',
              borderRightColor: 'rgba(226,94,71,0.3)',
            }}
          />
          {/* Middle ring */}
          <div
            className="absolute rounded-full spin-reverse"
            style={{
              inset: '12px',
              border: '1px solid transparent',
              borderTopColor: 'rgba(226,94,71,0.5)',
              borderBottomColor: 'rgba(226,94,71,0.2)',
            }}
          />
          {/* Inner glow circle */}
          <div
            className="absolute rounded-full"
            style={{
              inset: '28px',
              background: 'rgba(226,94,71,0.08)',
              border: '1px solid rgba(226,94,71,0.2)',
            }}
          />
          {/* Centre wordmark */}
          <span
            className="relative text-xl font-bold"
            style={{ fontFamily: 'Fira Code, monospace', color: '#e25e47' }}
          >
            q
          </span>
        </div>

        {/* Status text */}
        {error ? (
          <div className="text-center flex flex-col gap-3">
            <p className="text-lg font-semibold" style={{ color: '#ef4444' }}>Scan failed</p>
            <p className="text-sm" style={{ color: 'rgba(248,250,252,0.5)' }}>{error}</p>
            <button
              onClick={() => navigate('/')}
              className="mt-2 text-sm underline cursor-pointer"
              style={{ color: '#e25e47' }}
            >
              Try again
            </button>
          </div>
        ) : (
          <div className="text-center flex flex-col gap-2">
            <p className="text-base font-medium" style={{ color: 'rgba(248,250,252,0.85)' }}>
              {STEPS[stepIdx]}
            </p>
            <p className="text-xs" style={{ color: 'rgba(248,250,252,0.3)', fontFamily: 'Fira Code, monospace' }}>
              job {jobId?.slice(0, 8)}… · {status}
            </p>
          </div>
        )}

        {/* Progress bar */}
        {!error && (
          <div className="w-full flex flex-col gap-2">
            <div
              className="w-full h-1 rounded-full overflow-hidden"
              style={{ background: 'rgba(255,255,255,0.06)' }}
            >
              <div
                className="h-full rounded-full transition-all duration-700 ease-out"
                style={{
                  width: `${progress}%`,
                  background: 'linear-gradient(90deg, #e25e47, #f59e0b)',
                }}
              />
            </div>
            <div className="flex justify-between text-xs" style={{ color: 'rgba(248,250,252,0.2)', fontFamily: 'Fira Code, monospace' }}>
              <span>Step {stepIdx + 1}/{STEPS.length}</span>
              <span>{progress}%</span>
            </div>
          </div>
        )}

        {/* Steps list */}
        {!error && (
          <div className="w-full flex flex-col gap-1">
            {STEPS.map((step, i) => (
              <div
                key={step}
                className="flex items-center gap-3 px-4 py-2 rounded-lg transition-all duration-300"
                style={{
                  background: i === stepIdx ? 'rgba(226,94,71,0.08)' : 'transparent',
                  borderLeft: i === stepIdx ? '2px solid #e25e47' : '2px solid transparent',
                }}
              >
                <span
                  className="w-4 h-4 flex-shrink-0 flex items-center justify-center rounded-full text-xs"
                  style={{
                    background:
                      i < stepIdx
                        ? 'rgba(34,197,94,0.15)'
                        : i === stepIdx
                        ? 'rgba(226,94,71,0.15)'
                        : 'rgba(255,255,255,0.04)',
                    border:
                      i < stepIdx
                        ? '1px solid rgba(34,197,94,0.4)'
                        : i === stepIdx
                        ? '1px solid rgba(226,94,71,0.4)'
                        : '1px solid rgba(255,255,255,0.06)',
                  }}
                >
                  {i < stepIdx ? (
                    <svg width="8" height="8" viewBox="0 0 8 8" fill="none">
                      <path d="M1.5 4l2 2 3-3" stroke="#22c55e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  ) : i === stepIdx ? (
                    <span
                      className="w-1.5 h-1.5 rounded-full"
                      style={{ background: '#e25e47' }}
                    />
                  ) : null}
                </span>
                <span
                  className="text-xs"
                  style={{
                    color:
                      i < stepIdx
                        ? 'rgba(34,197,94,0.7)'
                        : i === stepIdx
                        ? 'rgba(248,250,252,0.85)'
                        : 'rgba(248,250,252,0.2)',
                    fontFamily: i === stepIdx ? 'Fira Code, monospace' : undefined,
                  }}
                >
                  {step}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
