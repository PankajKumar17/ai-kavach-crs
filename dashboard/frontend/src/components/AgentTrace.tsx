import { useEffect, useRef } from 'react';
import { CommandLineIcon, CheckCircleIcon, XCircleIcon, BoltIcon } from '@heroicons/react/24/outline';

interface AgentTraceProps {
  trace: string[];
  isLive?: boolean;
}

/* ─── Line classifier ────────────────────────────────── */
function classify(content: string): string {
  if (/FAIL|ERROR|Failed|❌/i.test(content))                     return 'text-red-400';
  if (/PASS|Success|successfully|✓|✅|🎉/i.test(content))       return 'text-brand-400 font-medium';
  if (/Phase\s+\d|Phase:/i.test(content))                        return 'text-cyan-400 font-semibold';
  if (/FINAL:/i.test(content))                                    return 'text-emerald-400 font-bold';
  if (/🛡️|={3,}/i.test(content))                                 return 'text-amber-400 font-semibold';
  if (/Running|Analyzing|Scanning|Attempting/i.test(content))    return 'text-zinc-300';
  return 'text-zinc-400';
}

function parseLine(raw: string) {
  const m = raw.match(/^\[(\d{2}:\d{2}:\d{2})\]\s*(.*)/);
  if (m) return { ts: m[1], content: m[2] };
  return { ts: null, content: raw };
}

/* ─── Component ──────────────────────────────────────── */
export function AgentTrace({ trace, isLive = false }: AgentTraceProps) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isLive && endRef.current) {
      endRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [trace, isLive]);

  const successCount = trace.filter(l => /PASS|Success|✓|✅/i.test(l)).length;
  const errorCount   = trace.filter(l => /FAIL|ERROR|Failed|❌/i.test(l)).length;

  return (
    <div className="card overflow-hidden">
      {/* Terminal header bar */}
      <div className="flex items-center justify-between px-5 py-3 bg-[#111113] dark:bg-[#0a0a0b] border-b border-white/[0.07]">
        {/* macOS dots */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/80"   />
            <span className="w-3 h-3 rounded-full bg-yellow-500/80"/>
            <span className="w-3 h-3 rounded-full bg-brand-500/80" />
          </div>
          <div className="flex items-center gap-2 text-zinc-400">
            <CommandLineIcon className="w-3.5 h-3.5" />
            <span className="text-xs font-mono">agent-trace</span>
          </div>
        </div>

        {isLive ? (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-brand-500/10 border border-brand-500/20">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-500" />
            </span>
            <span className="text-[11px] font-semibold text-brand-400 tracking-wide">LIVE</span>
          </div>
        ) : (
          <span className="text-[11px] text-zinc-600 font-mono">{trace.length} lines</span>
        )}
      </div>

      {/* Terminal body */}
      <div
        className="bg-[#0d0d10] dark:bg-[#080809] p-5 font-mono text-[13px] leading-6 overflow-y-auto"
        style={{ maxHeight: 420 }}
      >
        {trace.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 text-zinc-600">
            <BoltIcon className="w-10 h-10 mb-3 opacity-40" />
            <p className="text-sm">No trace data yet</p>
            <p className="text-xs mt-1 opacity-70">Click Start Analysis to see agent reasoning</p>
          </div>
        ) : (
          <div className="space-y-0">
            {trace.map((raw, i) => {
              const { ts, content } = parseLine(raw);
              const style = classify(content);
              return (
                <div key={i} className="flex items-start gap-3 hover:bg-white/[0.02] px-1 -mx-1 rounded transition-colors min-h-[24px]">
                  {ts && (
                    <span className="text-zinc-700 flex-shrink-0 select-none tabular-nums text-[11px] mt-0.5">
                      {ts}
                    </span>
                  )}
                  <span className={style}>{content || ' '}</span>
                </div>
              );
            })}
            <div ref={endRef} />
          </div>
        )}
      </div>

      {/* Footer stats */}
      <div className="flex items-center justify-between px-5 py-2.5 bg-[#111113] dark:bg-[#0a0a0b] border-t border-white/[0.07] text-[11px]">
        <div className="flex items-center gap-4 text-zinc-500">
          <span className="flex items-center gap-1.5">
            <CheckCircleIcon className="w-3.5 h-3.5 text-brand-500" />
            {successCount} passed
          </span>
          <span className="flex items-center gap-1.5">
            <XCircleIcon className="w-3.5 h-3.5 text-red-500" />
            {errorCount} errors
          </span>
          <span className="flex items-center gap-1.5">
            <BoltIcon className="w-3.5 h-3.5 text-cyan-500" />
            {trace.length} total lines
          </span>
        </div>
        {!isLive && trace.length > 0 && (
          <span className="text-zinc-600 font-mono">completed</span>
        )}
      </div>
    </div>
  );
}