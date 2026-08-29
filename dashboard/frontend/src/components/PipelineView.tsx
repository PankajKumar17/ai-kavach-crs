import { useState, useEffect, useRef, useCallback } from 'react';
import { RunSummary, Vulnerability } from '../types';
import { TargetCodebase, applyPatch, API_BASE } from '../api';
import {
  CommandLineIcon, CheckCircleIcon, XCircleIcon, ClockIcon,
  ShieldExclamationIcon, WrenchScrewdriverIcon, ChartBarIcon,
  ChevronDownIcon, ChevronRightIcon, ArrowPathIcon, SparklesIcon,
  BoltIcon, ExclamationTriangleIcon, FlagIcon, ShieldCheckIcon,
  InboxStackIcon, CpuChipIcon
} from '@heroicons/react/24/outline';
import { CheckBadgeIcon, RocketLaunchIcon } from '@heroicons/react/24/solid';

/* ─── Types ──────────────────────────────────────────── */
interface PipelineViewProps {
  target: TargetCodebase;
  runId: string;
  onBack: () => void;
  onReanalyze?: () => void;
  initialSummary?: RunSummary;
}

type PipelineStatus = 'connecting' | 'running' | 'done' | 'error';
type Phase = 'idle' | 'discovery' | 'scan' | 'llm' | 'complete';
type ResultTab = 'vulnerabilities' | 'patches';

/* ─── Phase detection ────────────────────────────────── */
function detectPhase(line: string): Phase | null {
  if (/Phase 1|Source Discovery|Instrumented Build/i.test(line)) return 'discovery';
  if (/Phase 2|Static Vuln|Fuzzing/i.test(line)) return 'scan';
  if (/Phase 3|Crash Triage|LLM Root|LLM client ready/i.test(line)) return 'llm';
  if (/FINAL:|Phase 4|Pipeline complete|RCA & Patch Generation/i.test(line)) return 'complete';
  return null;
}

const PHASES: { id: Phase; label: string }[] = [
  { id: 'discovery', label: 'Build / Discovery' },
  { id: 'scan',      label: 'Scan / Fuzzing' },
  { id: 'llm',       label: 'Triage & RCA' },
  { id: 'complete',  label: 'Patch & Verify' },
];

const PHASE_ORDER: Record<Phase, number> = {
  idle: 0, discovery: 1, scan: 2, llm: 3, complete: 4,
};

/* ─── Line coloring ──────────────────────────────────── */
function lineClass(line: string): string {
  if (/FINAL:|PASS/i.test(line))                                       return 'text-emerald-400 font-bold';
  if (/✓|Success|Resolved|Patched|✅/i.test(line))                     return 'text-brand-400';
  if (/✗|FAIL|ERROR|Failed|❌/i.test(line))                            return 'text-red-400';
  if (/⚑|\[CRITICAL\]|\[HIGH\]/i.test(line))                          return 'text-orange-400';
  if (/⚑|\[MEDIUM\]|\[LOW\]/i.test(line))                             return 'text-yellow-400';
  if (/Phase \d|════/i.test(line))                                     return 'text-cyan-400 font-semibold';
  if (/🛡️|AI KAVACH/i.test(line))                                      return 'text-brand-300 font-bold';
  if (/Provider|Model|Target|Run ID/i.test(line))                      return 'text-zinc-300';
  if (/⚠|ℹ /i.test(line))                                              return 'text-amber-400';
  return 'text-zinc-400';
}

/* ─── Severity config ─────────────────────────────────── */
const SEV: Record<string, { dot: string; badge: string; border: string }> = {
  CRITICAL: { dot: 'bg-red-500',    badge: 'bg-red-500/10 text-red-400',    border: 'border-red-500/20' },
  HIGH:     { dot: 'bg-orange-500', badge: 'bg-orange-500/10 text-orange-400', border: 'border-orange-500/20' },
  MEDIUM:   { dot: 'bg-yellow-500', badge: 'bg-yellow-500/10 text-yellow-400', border: 'border-yellow-500/20' },
  LOW:      { dot: 'bg-green-500',  badge: 'bg-green-500/10 text-green-400', border: 'border-green-500/20' },
};

/* ─── Log Line Renderer ──────────────────────────────── */
const EMOJI_MAP: Record<string, React.ElementType> = {
  '🛡️': ShieldCheckIcon,
  '🔮': SparklesIcon,
  '✓': CheckCircleIcon,
  '✅': CheckCircleIcon,
  '✗': XCircleIcon,
  '❌': XCircleIcon,
  '⚐': FlagIcon,
  '⚑': FlagIcon,
  '⚠️': ExclamationTriangleIcon,
  '⚠': ExclamationTriangleIcon,
  '📊': ChartBarIcon,
  '🛡': ShieldCheckIcon,
};

function LogLineRender({ line }: { line: string }) {
  // Extract timestamp like [22:22:04]
  const timeMatch = line.match(/^(\[\d\d:\d\d:\d\d\])(.*)$/);
  
  if (!timeMatch) {
    return (
      <div className={`flex gap-3 min-h-[28px] hover:bg-white/[0.03] px-2 -mx-2 rounded transition-colors`}>
        <span className={lineClass(line)}>{line || ' '}</span>
      </div>
    );
  }

  const timestamp = timeMatch[1];
  let rest = timeMatch[2];
  let Icon = null;
  
  // Find any known emoji in the rest of the string
  const emojiMatch = rest.match(/(🔮|✓|✗|✅|❌|🛡️|🛡|⚐|⚑|⚠️|⚠|📊|ℹ)/);
  if (emojiMatch) {
    const emoji = emojiMatch[1];
    Icon = EMOJI_MAP[emoji];
    rest = rest.replace(emoji, '').trim();
  } else {
    rest = rest.trim();
  }

  return (
    <div className={`flex gap-2 min-h-[28px] hover:bg-white/[0.03] px-2 -mx-2 rounded transition-colors items-start py-0.5`}>
      <span className="text-zinc-500 flex-shrink-0 mt-[2px]">{timestamp}</span>
      <span className={`${lineClass(line)} flex items-start gap-1.5 flex-1`}>
        {Icon ? (
          <>
            <Icon className="w-[15px] h-[15px] flex-shrink-0 mt-[1.5px]" />
            <span className="leading-relaxed break-words">{rest}</span>
          </>
        ) : (
          <span className="leading-relaxed break-words">{rest}</span>
        )}
      </span>
    </div>
  );
}

/* ─── Vuln Detail Row (expandable) ───────────────────── */
function VulnRow({ v }: { v: Vulnerability }) {
  const [open, setOpen] = useState(false);
  const s = SEV[v.severity] ?? SEV.LOW;
  const isResolved = v.status === 'Resolved';

  return (
    <>
      <tr
        className="border-b border-gray-100 dark:border-white/[0.04] hover:bg-gray-50/50 dark:hover:bg-white/[0.02] cursor-pointer transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <td className="px-5 py-4">
          <div className="flex items-center gap-2.5">
            {open
              ? <ChevronDownIcon className="w-4 h-4 text-gray-400 dark:text-zinc-500 flex-shrink-0" />
              : <ChevronRightIcon className="w-4 h-4 text-gray-400 dark:text-zinc-500 flex-shrink-0" />}
            <code className="font-mono text-[13px] text-brand-600 dark:text-brand-400 font-medium">{v.id}</code>
          </div>
        </td>
        <td className="px-5 py-4">
          <span className="text-[13px] font-semibold text-gray-900 dark:text-white">{v.type}</span>
        </td>
        <td className="px-5 py-4">
          <code className="font-mono text-xs text-gray-500 dark:text-surface-400">{v.location}</code>
        </td>
        <td className="px-5 py-4">
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${s.badge} ${s.border} bg-white dark:bg-transparent shadow-sm`}>
            <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
            {v.severity}
          </span>
        </td>
        <td className="px-5 py-4">
          {isResolved
            ? <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
                <CheckBadgeIcon className="w-4 h-4" /> Resolved
              </span>
            : v.status === 'False Positive'
            ? <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-600 dark:text-blue-400">
                <CheckCircleIcon className="w-4 h-4" /> False Positive
              </span>
            : v.status === 'Pending'
            ? <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 dark:text-surface-400">
                <ClockIcon className="w-4 h-4" /> Pending
              </span>
            : <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-600 dark:text-red-400">
                <XCircleIcon className="w-4 h-4" /> {v.status}
              </span>
          }
        </td>
        <td className="px-5 py-4 text-xs font-medium text-gray-500 dark:text-surface-400">{v.agent}</td>
        <td className="px-5 py-4 text-right">
          <code className="font-mono text-xs text-gray-500 dark:text-surface-400">{v.time_taken}</code>
        </td>
      </tr>

      {/* Expanded detail */}
      {open && (
        <tr className="bg-gray-50/50 dark:bg-white/[0.01] border-b border-gray-100 dark:border-white/[0.04]">
          <td colSpan={7} className="px-6 py-5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {v.asan_trace && (
                <div className="md:col-span-2">
                  <p className="text-xs font-semibold text-gray-600 dark:text-surface-300 mb-2">
                    Sanitizer Evidence{v.crash_count ? ` · ${v.crash_count} crash input(s)` : ''}
                  </p>
                  <pre className="font-mono text-[11px] leading-5 bg-[#0d0d10] border border-red-500/20 rounded-xl p-4 text-red-300 overflow-x-auto shadow-sm max-h-56">
                    {v.asan_trace}
                  </pre>
                </div>
              )}
              {v.line_text && (
                <div>
                  <p className="text-xs font-semibold text-gray-600 dark:text-surface-300 mb-2">Affected Code</p>
                  <pre className="font-mono text-xs bg-white dark:bg-[#070709] border border-gray-200 dark:border-white/[0.08] rounded-xl p-4 text-orange-600 dark:text-orange-300 overflow-x-auto shadow-sm">
                    {v.line_text}
                  </pre>
                </div>
              )}
              {v.rca && (
                <div>
                  <p className="text-xs font-semibold text-gray-600 dark:text-surface-300 mb-2">Root Cause</p>
                  <div className="text-[13px] text-gray-700 dark:text-zinc-300 bg-white dark:bg-[#070709] border border-gray-200 dark:border-white/[0.08] rounded-xl p-4 leading-relaxed shadow-sm">
                    {v.rca}
                  </div>
                </div>
              )}
              {v.fix_hint && (
                <div className="md:col-span-2">
                  <p className="text-xs font-semibold text-gray-600 dark:text-surface-300 mb-2">Remediation</p>
                  <div className="text-[13px] text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-500/5 border border-emerald-200 dark:border-emerald-500/20 rounded-xl p-4 leading-relaxed shadow-sm">
                    {v.fix_hint}
                  </div>
                </div>
              )}
              {!v.rca && !v.fix_hint && !v.line_text && (
                <p className="text-sm text-gray-500 dark:text-surface-400 col-span-2 italic">No additional details available for this finding.</p>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/* ─── Patch Card — diff view + Apply Fix ─────────────── */
function PatchCard({ v, targetId, runId, onPatchApplied }: {
  v: Vulnerability;
  targetId: string;
  runId: string;
  onPatchApplied: (vulnId: string) => void;
}) {
  const s = SEV[v.severity] ?? SEV.LOW;

  // A patch exists if we have the unified diff OR the single-line fallback
  const hasPatch   = !!(
    (v.patch_diff || v.patched_line) &&
    v.file_path &&
    v.line_number
  );

  const [applyState, setApplyState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle');
  const [applyError, setApplyError] = useState('');

  const handleApply = async () => {
    if (!hasPatch) return;
    setApplyState('loading');
    setApplyError('');
    try {
      await applyPatch({
        targetId,
        runId,
        vulnId:       v.id,
        filePath:     v.file_path!,
        lineNumber:   v.line_number!,
        originalLine: v.line_text ?? '',
        patchedLine:  v.patched_line ?? '',
        patchDiff:    v.patch_diff ?? '',    // preferred — uses git apply
      });
      setApplyState('done');
      onPatchApplied(v.id);
    } catch (e: unknown) {
      setApplyError(e instanceof Error ? e.message : String(e));
      setApplyState('error');
    }
  };

  // Patch tier badge config
  const TIER_BADGE: Record<string, { label: React.ReactNode; cls: string }> = {
    template: { label: <span className="flex items-center gap-1.5"><BoltIcon className="w-3.5 h-3.5" /> Template</span>, cls: 'bg-amber-500/10 text-amber-500 dark:text-amber-400 border-amber-500/20' },
    cached:   { label: <span className="flex items-center gap-1.5"><InboxStackIcon className="w-3.5 h-3.5" /> Cached</span>,   cls: 'bg-blue-500/10 text-blue-500 dark:text-blue-400 border-blue-500/20' },
    llm:      { label: <span className="flex items-center gap-1.5"><CpuChipIcon className="w-3.5 h-3.5" /> LLM</span>,      cls: 'bg-purple-500/10 text-purple-500 dark:text-purple-400 border-purple-500/20' },
    none:     { label: 'No patch',    cls: 'bg-zinc-800/40 text-zinc-600 border-zinc-700/30' },
  };
  const tierKey = v.patch_tier ?? 'none';
  const tier = TIER_BADGE[tierKey] ?? TIER_BADGE.none;

  // Critic verdict rendering
  const criticIsApproved   = v.critic_verdict === 'approved';
  const criticIsConcern    = v.critic_verdict?.startsWith('concern:');
  const criticIsUnavail    = v.critic_verdict?.startsWith('critic_unavailable') || v.critic_verdict?.startsWith('critic_error');

  // Parse diff lines for display (use patch_diff if present, else synthesise from patched_line)
  const diffLines: { type: 'minus' | 'plus' | 'ctx'; text: string }[] = [];
  if (v.patch_diff) {
    for (const line of v.patch_diff.split('\n')) {
      if (line.startsWith('---') || line.startsWith('+++') || line.startsWith('@@')) continue;
      if (line.startsWith('-')) diffLines.push({ type: 'minus', text: line.slice(1) });
      else if (line.startsWith('+')) diffLines.push({ type: 'plus', text: line.slice(1) });
      else diffLines.push({ type: 'ctx', text: line.slice(1) });
    }
  } else if (v.line_text || v.patched_line) {
    if (v.line_text)    diffLines.push({ type: 'minus', text: v.line_text });
    if (v.patched_line) diffLines.push({ type: 'plus',  text: v.patched_line });
  }
  return (
    <div className={`card p-0 border overflow-hidden ${s.border.replace('/20', '/40')} shadow-md`}>
      {/* Header */}
      <div className={`px-5 py-4 border-b ${s.border} bg-${s.dot.replace('bg-','')}/5 dark:bg-${s.dot.replace('bg-','')}/10 flex items-center justify-between gap-3`}>
        <div className="flex items-center gap-3.5 min-w-0">
          <span className={`w-3.5 h-3.5 rounded-full ${s.dot} shadow-sm flex-shrink-0 animate-pulse`} />
          <div className="min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <p className="text-sm font-bold text-gray-900 dark:text-white truncate">{v.type}</p>
              {/* CWE badge */}
              {v.cwe && v.cwe !== 'CWE-unknown' && (
                <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-white dark:bg-surface-800 text-gray-600 dark:text-surface-300 border border-gray-200 dark:border-white/[0.08] shadow-sm">
                  {v.cwe}
                </span>
              )}
              {/* Patch tier badge */}
              {hasPatch && (
                <span className={`px-2 py-0.5 rounded-md text-[11px] font-semibold border bg-white dark:bg-transparent ${tier.cls} shadow-sm`}>
                  {tier.label}
                </span>
              )}
            </div>
            <code className="text-xs text-gray-500 dark:text-surface-400 font-mono mt-1 block">{v.location}</code>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${s.badge} ${s.border} bg-white dark:bg-transparent shadow-sm`}>{v.severity}</span>
          {v.status === 'Resolved'
            ? <span className="flex items-center gap-1 text-xs font-semibold text-emerald-600 dark:text-emerald-400"><CheckBadgeIcon className="w-4 h-4" /> Resolved</span>
            : v.status === 'False Positive'
            ? <span className="flex items-center gap-1 text-xs font-semibold text-blue-600 dark:text-blue-400"><CheckCircleIcon className="w-4 h-4" /> False Pos</span>
            : <span className="flex items-center gap-1 text-xs font-semibold text-gray-500 dark:text-surface-400"><ClockIcon className="w-4 h-4" /> {v.status}</span>
          }
        </div>
      </div>

      {/* Body */}
      <div className="p-5 space-y-4">

        {/* Root cause */}
        {v.rca && (
          <div>
            <p className="text-xs font-semibold text-gray-600 dark:text-surface-300 mb-1.5">Root Cause</p>
            <p className="text-[13px] text-gray-700 dark:text-zinc-300 leading-relaxed">{v.rca}</p>
          </div>
        )}

        {/* Diff view */}
        {diffLines.length > 0 && (
          <div className="rounded-xl overflow-hidden border border-gray-200 dark:border-white/[0.08] shadow-sm bg-white dark:bg-[#070709]">
            <div className="flex items-center gap-2 px-4 py-2.5 bg-gray-50 dark:bg-surface-800/80 border-b border-gray-200 dark:border-white/[0.05]">
              <span className="text-[11px] font-bold text-gray-500 dark:text-surface-400 font-mono uppercase tracking-wider">Patch Diff</span>
              {v.line_number && <span className="text-xs text-gray-400 dark:text-surface-500 ml-auto">line {v.line_number}</span>}
              {applyState === 'done' && (
                <span className="text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-1"><CheckCircleIcon className="w-3 h-3"/> Applied</span>
              )}
            </div>
            <div className="font-mono text-[13px] overflow-x-auto py-2">
              {diffLines.map((dl, i) => (
                <div key={i} className={
                  dl.type === 'minus' ? 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-300 px-4 py-1' :
                  dl.type === 'plus'  ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 px-4 py-1' :
                  'text-gray-600 dark:text-surface-400 px-4 py-1'
                }>
                  <span className={`select-none mr-3 ${dl.type === 'minus' ? 'text-red-400' : dl.type === 'plus' ? 'text-emerald-400' : 'text-gray-300 dark:text-surface-600'}`}>
                    {dl.type === 'minus' ? '-' : dl.type === 'plus' ? '+' : ' '}
                  </span>
                  {dl.text}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* No analysis */}
        {!v.rca && diffLines.length === 0 && (
          <div className="flex items-center gap-2 text-gray-500 dark:text-surface-400 bg-gray-50 dark:bg-surface-900 px-4 py-3 rounded-xl border border-gray-100 dark:border-white/[0.04]">
            <SparklesIcon className="w-5 h-5 text-gray-400" />
            <p className="text-[13px] font-medium">No AI analysis available.</p>
          </div>
        )}

        {/* Critic verdict row */}
        {v.critic_verdict && v.critic_verdict !== 'no_patch' && v.critic_verdict !== 'skipped' && (
          <div className={`flex items-start gap-2 rounded-xl px-4 py-3 text-[13px] border shadow-sm ${
            criticIsApproved
              ? 'bg-emerald-50 dark:bg-emerald-500/5 border-emerald-200 dark:border-emerald-500/20 text-emerald-800 dark:text-emerald-300'
              : criticIsConcern
              ? 'bg-amber-50 dark:bg-amber-500/5 border-amber-200 dark:border-amber-500/20 text-amber-800 dark:text-amber-300'
              : 'bg-gray-50 dark:bg-surface-800/50 border-gray-200 dark:border-white/[0.08] text-gray-600 dark:text-surface-300'
          }`}>
            <span className="flex-shrink-0 mt-0.5">
              {criticIsApproved ? <CheckCircleIcon className="w-4 h-4" /> : criticIsConcern ? <ExclamationTriangleIcon className="w-4 h-4" /> : criticIsUnavail ? <BoltIcon className="w-4 h-4" /> : <SparklesIcon className="w-4 h-4" />}
            </span>
            <span className="leading-relaxed">
              <span className="font-semibold">Critic: </span>
              {criticIsApproved ? 'Verified: Patch resolves the vulnerability.'
                : criticIsConcern ? v.critic_verdict.replace('concern: ', '')
                : v.critic_verdict}
            </span>
          </div>
        )}

        {/* Footer: Apply Fix button */}
        <div className="flex items-center justify-between pt-2 border-t border-gray-100 dark:border-white/[0.04]">
          <span className="text-xs font-medium text-gray-500 dark:text-surface-400">Agent: {v.agent} • {v.time_taken}</span>

          {hasPatch && applyState !== 'done' && v.status !== 'False Positive' && (
            <button
              onClick={handleApply}
              disabled={applyState === 'loading'}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-[13px] font-semibold transition-all duration-200 shadow-sm ${
                applyState === 'error'
                  ? 'bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-500/20'
                  : 'bg-brand-50 dark:bg-brand-500/10 border border-brand-200 dark:border-brand-500/30 text-brand-700 dark:text-brand-400 hover:bg-brand-100 dark:hover:bg-brand-500/20'
              } disabled:opacity-50`}
            >
              {applyState === 'loading'
                ? <><ArrowPathIcon className="w-4 h-4 animate-spin" /> Applying…</>
                : applyState === 'error'
                ? <><XCircleIcon className="w-4 h-4" /> Retry</>
                : <><BoltIcon className="w-4 h-4" /> Apply Patch</>
              }
            </button>
          )}

          {applyState === 'done' && (
            <span className="flex items-center gap-1.5 text-[13px] font-semibold text-emerald-600 dark:text-emerald-400">
              <CheckBadgeIcon className="w-5 h-5" /> Patch applied
            </span>
          )}
        </div>

        {/* Apply error */}
        {applyState === 'error' && applyError && (
          <p className="text-[13px] text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-xl px-4 py-3 shadow-sm">
            {applyError}
          </p>
        )}
      </div>
    </div>
  );
}


/* ─── Main PipelineView ──────────────────────────────── */
export function PipelineView({ target, runId, onBack, onReanalyze, initialSummary }: PipelineViewProps) {
  const [status, setStatus]       = useState<PipelineStatus>(initialSummary ? 'done' : 'connecting');
  const [phase, setPhase]         = useState<Phase>(initialSummary ? 'complete' : 'idle');
  const [trace, setTrace]         = useState<string[]>(initialSummary?.agent_trace ?? []);
  const [summary, setSummary]     = useState<RunSummary | null>(initialSummary ?? null);
  const [activeTab, setActiveTab] = useState<ResultTab>('vulnerabilities');
  const [elapsed, setElapsed]     = useState(initialSummary ? (initialSummary.average_time_per_verified_patch_s || 0) * (initialSummary.vulnerabilities?.length || 1) : 0);
  const [fileCount, setFileCount] = useState<number | null>(null);
  const [issueCount, setIssueCount] = useState<number | null>(initialSummary ? (initialSummary.vulnerabilities?.length || 0) : null);
  const [llmProgress, setLlmProgress] = useState<{ done: number; total: number } | null>(null);

  const termRef  = useRef<HTMLDivElement>(null);
  const esRef    = useRef<EventSource | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startRef = useRef<number>(Date.now());

  /* ─── Live stats extraction ─────────────────────── */
  const extractStats = useCallback((line: string) => {
    const fileMatch = line.match(/Found (\d+) source files/i);
    if (fileMatch) setFileCount(parseInt(fileMatch[1]));

    const issueMatch = line.match(/(\d+)\s+(?:potential\s+)?issues?\s+found|(\d+)\s+found/i);
    if (issueMatch) setIssueCount(parseInt(issueMatch[1] ?? issueMatch[2]));

    const llmMatch = line.match(/\[(\d+)\/(\d+)\] Analyzing/i);
    if (llmMatch) setLlmProgress({ done: parseInt(llmMatch[1]), total: parseInt(llmMatch[2]) });
  }, []);

  /* ─── SSE connection ────────────────────────────── */
  useEffect(() => {
    // If we have an initial summary, we don't start the engine.
    if (initialSummary) {
      // Just extract fileCount from the trace if possible
      initialSummary.agent_trace?.forEach(extractStats);
      return;
    }

    const token = import.meta.env.VITE_ENGINE_AUTH_TOKEN;
    const url = `${API_BASE}/api/engine/stream?target_id=${encodeURIComponent(target.id)}&run_id=${encodeURIComponent(runId)}${token ? `&token=${encodeURIComponent(token)}` : ''}`;
    const es = new EventSource(url);
    esRef.current = es;
    startRef.current = Date.now();

    // Start elapsed timer
    timerRef.current = setInterval(() => {
      setElapsed(Math.round((Date.now() - startRef.current) / 1000));
    }, 1000);

    setStatus('running');

    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as { line: string };
        const line = data.line;
        setTrace(prev => [...prev, line]);
        const newPhase = detectPhase(line);
        if (newPhase) {
          setPhase(p => PHASE_ORDER[newPhase] > PHASE_ORDER[p] ? newPhase : p);
        }
        extractStats(line);
        // Auto-scroll terminal
        requestAnimationFrame(() => {
          if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
        });
      } catch (_) { /* ignore parse errors */ }
    };

    es.addEventListener('complete', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as { status: string; summary?: RunSummary };
        setStatus(data.status === 'success' ? 'done' : 'error');
        setPhase('complete');
        if (data.summary) setSummary(data.summary);
      } catch (_) { setStatus('done'); }
      es.close();
      if (timerRef.current) clearInterval(timerRef.current);
    });

    es.onerror = () => {
      // Native EventSource error (connection refused, CORS, etc.)
      setTrace(prev => [
        ...prev,
        '[ERROR] Connection to pipeline failed. Is the server running?',
      ]);
      setStatus('error');
      es.close();
      if (timerRef.current) clearInterval(timerRef.current);
    };

    return () => {
      es.close();
      if (timerRef.current) clearInterval(timerRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ─── Derived values ────────────────────────────── */
  const vulns  = summary?.vulnerabilities ?? [];
  const resolved = vulns.filter(v => v.status === 'Resolved').length;
  const total    = vulns.length;
  const successRate = total > 0 ? Math.round(resolved / total * 100) : 0;

  const isDone       = status === 'done' || status === 'error';
  const currentPhaseIdx = PHASES.findIndex(p => p.id === phase);

  /* ─── Render ────────────────────────────────────── */
  return (
    <div className="space-y-6 animate-fade-in">

      {/* ── Phase progress ──────────────────────────── */}
      <div className="card p-0 overflow-hidden">
        <div className="flex items-center justify-between flex-wrap gap-4 p-5 bg-gray-50/50 dark:bg-white/[0.02] border-b border-gray-100 dark:border-white/[0.04]">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-brand-50 dark:bg-brand-500/10 border border-brand-100 dark:border-brand-500/20 flex items-center justify-center">
              <ShieldExclamationIcon className="w-5 h-5 text-brand-600 dark:text-brand-400" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-gray-900 dark:text-white tracking-tight">
                {initialSummary ? 'Results:' : 'Analyzing:'} <span className="text-brand-600 dark:text-brand-400 font-medium">{target.name}</span>
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Live stats pills */}
            {fileCount !== null && (
              <span className="px-3 py-1.5 rounded-full bg-white dark:bg-surface-800 border border-gray-200 dark:border-white/[0.08] text-xs font-medium text-gray-700 dark:text-surface-300 shadow-sm">
                📁 {fileCount} Files
              </span>
            )}
            {issueCount !== null && (
              <span className="px-3 py-1.5 rounded-full bg-orange-50 dark:bg-orange-500/10 border border-orange-200 dark:border-orange-500/20 text-xs font-medium text-orange-700 dark:text-orange-400 shadow-sm">
                ⚑ {issueCount} Issues
              </span>
            )}
            {llmProgress && (
              <span className="px-3 py-1.5 rounded-full bg-cyan-50 dark:bg-cyan-500/10 border border-cyan-200 dark:border-cyan-500/20 text-xs font-medium text-cyan-700 dark:text-cyan-400 shadow-sm">
                 LLM {llmProgress.done}/{llmProgress.total}
              </span>
            )}
            <span className="px-3 py-1.5 rounded-full bg-white dark:bg-surface-800 border border-gray-200 dark:border-white/[0.08] text-xs font-medium text-gray-600 dark:text-surface-400 shadow-sm">
              ⏱ {elapsed}s
            </span>
            {!isDone && (
              <span className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-brand-50 dark:bg-brand-500/10 border border-brand-200 dark:border-brand-500/20 text-xs font-semibold text-brand-700 dark:text-brand-400 shadow-sm">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inset-0 rounded-full bg-brand-400 opacity-75" />
                  <span className="relative rounded-full h-2 w-2 bg-brand-500" />
                </span>
                LIVE
              </span>
            )}
            {isDone && status === 'done' && (
              <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/20 text-xs font-semibold text-emerald-700 dark:text-emerald-400 shadow-sm">
                <CheckCircleIcon className="w-4 h-4" /> Done
              </span>
            )}
            {onReanalyze && (
              <button
                onClick={onReanalyze}
                className="btn-primary ml-2 !py-1.5 !px-3 text-xs shadow-sm"
              >
                <RocketLaunchIcon className="w-3.5 h-3.5" />
                Re-analyze
              </button>
            )}
          </div>
        </div>

        {/* Phase stepper */}
        <div className="flex items-center gap-0 p-5 overflow-hidden">
          {PHASES.map((p, i) => (
            <div key={p.id} className="flex items-center flex-1">
              <div className="flex flex-col items-center flex-shrink-0 z-10 relative bg-white dark:bg-surface-800/80 px-2">
                <div className={`w-8 h-8 rounded-full border-2 flex items-center justify-center transition-all duration-300 ${
                  status === 'error' && currentPhaseIdx === i
                    ? 'bg-red-50 dark:bg-red-500/10 border-red-500 text-red-500'
                    : (status === 'done' ? i <= currentPhaseIdx : currentPhaseIdx > i)
                    ? 'bg-brand-500 border-brand-500 text-white shadow-[0_0_12px_rgba(16,185,129,0.4)]'
                    : currentPhaseIdx === i && !isDone
                    ? 'bg-brand-50 dark:bg-brand-500/10 border-brand-400 animate-pulse text-brand-600 dark:text-brand-400'
                    : 'bg-gray-50 dark:bg-surface-900 border-gray-200 dark:border-white/[0.1] text-gray-400 dark:text-surface-500'
                }`}>
                  {status === 'error' && currentPhaseIdx === i
                    ? <XCircleIcon className="w-5 h-5" />
                    : (status === 'done' ? i <= currentPhaseIdx : currentPhaseIdx > i)
                    ? <CheckCircleIcon className="w-5 h-5" />
                    : <span className="text-xs font-bold">{i + 1}</span>
                  }
                </div>
                <span className={`text-[11px] mt-2 font-medium whitespace-nowrap transition-colors ${
                  currentPhaseIdx >= i ? 'text-gray-900 dark:text-white font-semibold' : 'text-gray-500 dark:text-surface-400'
                }`}>{p.label}</span>
              </div>
              {i < PHASES.length - 1 && (
                <div className="flex-1 -ml-2 -mr-2 mb-5 h-0.5 relative rounded-full overflow-hidden bg-gray-100 dark:bg-white/[0.04]">
                   <div className={`absolute inset-0 transition-all duration-500 ${
                     (status === 'done' ? i < currentPhaseIdx : currentPhaseIdx > i) ? 'bg-brand-500 w-full' : 'w-0'
                   }`} />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>


      {/* ── Main content: terminal + stats ──────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Terminal — takes 2/3 */}
        <div className="lg:col-span-2 card p-0 bg-[#070709] dark:bg-[#070709] flex flex-col h-[500px] shadow-[0_8px_30px_rgb(0,0,0,0.12)]">
          {/* Terminal chrome */}
          <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.06] bg-[#0a0a0c]">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-zinc-400">
                <CommandLineIcon className="w-4 h-4" />
                <span className="text-xs font-medium font-mono text-zinc-300">pipeline — {target.name}</span>
              </div>
            </div>
            {!isDone && (
              <ArrowPathIcon className="w-4 h-4 text-brand-400 animate-spin" />
            )}
          </div>

          {/* Terminal body */}
          <div
            ref={termRef}
            className="p-5 font-mono text-[13px] leading-relaxed overflow-y-scroll flex-1 min-h-0 bg-transparent text-zinc-300"
          >
            {status === 'connecting' ? (
              <div className="flex items-center gap-3 text-zinc-500 mt-4">
                <ArrowPathIcon className="w-5 h-5 animate-spin text-brand-500" />
                <span>Connecting to pipeline server…</span>
              </div>
            ) : trace.length === 0 ? (
              <div className="text-zinc-500 mt-4">Waiting for output…</div>
            ) : (
              trace.map((line, i) => (
                <LogLineRender key={i} line={line} />
              ))
            )}
          </div>

          {/* Terminal footer */}
          <div className="px-5 py-2.5 bg-[#0a0a0c] border-t border-white/[0.06] flex items-center justify-between text-xs font-medium text-zinc-500">
            <span>{trace.length} lines processed</span>
            <span className="font-mono">{elapsed}s elapsed</span>
          </div>
        </div>

        {/* Right stats panel — 1/3 */}
        <div className="lg:col-span-1 flex flex-col gap-4">
          {/* Running telemetry state */}
          {!isDone && (
            <div className="card p-6 flex flex-col justify-between h-full bg-white dark:bg-surface-800/50">
              <div>
                <div className="flex items-center gap-3 mb-6">
                  <div className="relative flex h-3 w-3">
                    <span className="animate-ping absolute inset-0 rounded-full bg-brand-400 opacity-75" />
                    <span className="relative rounded-full h-3 w-3 bg-brand-500" />
                  </div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wider">Live Telemetry</h3>
                </div>
                
                <div className="space-y-5">
                  <div>
                    <p className="text-[11px] font-semibold text-gray-500 dark:text-surface-400 uppercase tracking-wider mb-1">Current Phase</p>
                    <p className="text-lg font-bold text-brand-600 dark:text-brand-400 animate-pulse">{PHASES.find(p => p.id === phase)?.label || 'Connecting...'}</p>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4 pt-4 border-t border-gray-100 dark:border-white/[0.04]">
                    <div>
                      <p className="text-[11px] font-semibold text-gray-500 dark:text-surface-400 uppercase tracking-wider mb-1">Files Scanned</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-white">{fileCount ?? '--'}</p>
                    </div>
                    <div>
                      <p className="text-[11px] font-semibold text-gray-500 dark:text-surface-400 uppercase tracking-wider mb-1">Issues Found</p>
                      <p className={`text-2xl font-bold ${issueCount && issueCount > 0 ? 'text-orange-500' : 'text-gray-900 dark:text-white'}`}>{issueCount ?? '--'}</p>
                    </div>
                  </div>
                  
                  {llmProgress && (
                    <div className="pt-4 border-t border-gray-100 dark:border-white/[0.04]">
                      <div className="flex justify-between items-end mb-2">
                        <p className="text-[11px] font-semibold text-gray-500 dark:text-surface-400 uppercase tracking-wider">AI Analysis Progress</p>
                        <p className="text-xs font-bold text-gray-900 dark:text-white">{llmProgress.done} / {llmProgress.total}</p>
                      </div>
                      <div className="h-2 w-full bg-gray-100 dark:bg-surface-900 rounded-full overflow-hidden border border-gray-200 dark:border-white/[0.04]">
                        <div 
                          className="h-full bg-brand-500 transition-all duration-300"
                          style={{ width: `${Math.round((llmProgress.done / Math.max(llmProgress.total, 1)) * 100)}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="mt-6 pt-4 border-t border-gray-100 dark:border-white/[0.04] flex justify-between items-center text-xs font-medium text-gray-500 dark:text-surface-400">
                <span>Duration</span>
                <span className="font-mono text-gray-900 dark:text-white">{elapsed}s</span>
              </div>
            </div>
          )}

          {/* Results preview (shows after done) */}
          {isDone && summary && (
            <div className="card p-6 animate-slide-up flex-1 flex flex-col justify-center gap-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-500 dark:text-surface-400 mb-2 uppercase tracking-wider text-center">Results Preview</h3>
                <div className="text-center py-4">
                  <p className={`text-6xl font-bold tracking-tight mb-2 ${successRate >= 80 ? 'text-brand-500' : successRate >= 50 ? 'text-yellow-500' : 'text-red-500'}`}>
                    {successRate}%
                  </p>
                  <p className="text-sm font-medium text-gray-600 dark:text-surface-300">Success Rate</p>
                  <p className="text-xs text-gray-500 dark:text-surface-400 mt-2">{resolved} of {total} issues resolved</p>
                </div>
                
                {total > 0 && (
                  <div className="mt-4 pt-4 border-t border-gray-100 dark:border-white/[0.04] space-y-2">
                    {[
                      { label: 'CRITICAL', count: vulns.filter(v => v.severity === 'CRITICAL').length, color: 'bg-red-500' },
                      { label: 'HIGH',     count: vulns.filter(v => v.severity === 'HIGH').length,     color: 'bg-orange-500' },
                      { label: 'MEDIUM',   count: vulns.filter(v => v.severity === 'MEDIUM').length,   color: 'bg-yellow-500' },
                      { label: 'LOW',      count: vulns.filter(v => v.severity === 'LOW').length,       color: 'bg-brand-500' },
                    ].filter(r => r.count > 0).map(r => (
                      <div key={r.label} className="flex items-center gap-2.5">
                        <span className={`w-2.5 h-2.5 rounded-full ${r.color} shadow-sm`} />
                        <span className="text-xs font-medium text-gray-600 dark:text-surface-300 flex-1">{r.label}</span>
                        <span className="text-xs font-semibold text-gray-900 dark:text-white bg-gray-100 dark:bg-surface-800 px-2 py-0.5 rounded-md">{r.count}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Overview Metrics */}
              <div className="pt-6 border-t border-gray-100 dark:border-white/[0.04] grid grid-cols-2 gap-4">
                {[
                  { label: 'Time to detect', value: `${(summary.average_time_per_verified_patch_s / 2).toFixed(1)}s`, color: 'text-blue-500 dark:text-blue-400' },
                  { label: 'Time to resolve', value: `${summary.average_time_per_verified_patch_s.toFixed(1)}s`, color: 'text-violet-500 dark:text-violet-400' },
                  { label: 'Auto-patched', value: `${successRate}%`, color: 'text-amber-500 dark:text-amber-400' },
                  { label: 'Duration', value: `${summary.total_time_s ? summary.total_time_s.toFixed(1) : elapsed}s`, color: 'text-gray-900 dark:text-white' }
                ].map(m => (
                  <div key={m.label} className="bg-gray-50 dark:bg-surface-800/50 p-3 rounded-xl border border-gray-200 dark:border-white/[0.04] text-center">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-500 dark:text-surface-400 mb-1">{m.label}</p>
                    <p className={`text-lg font-bold ${m.color}`}>{m.value}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Error state */}
          {status === 'error' && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 animate-slide-up">
              <p className="text-sm font-semibold text-red-400 mb-1">Pipeline Error</p>
              <p className="text-xs text-red-300/70">Check the terminal output above for details</p>
              <button onClick={onBack} className="mt-3 btn-secondary text-xs">
                ← Go Back
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── Results tabs (after completion) ─────────── */}
      {isDone && summary && (
        <div className="space-y-4 animate-slide-up">
          {/* Tab bar */}
          <div className="flex items-center gap-1.5 p-1.5 rounded-2xl bg-gray-100/80 dark:bg-surface-900/50 border border-gray-200 dark:border-white/[0.04] w-fit">
            {([
              { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldExclamationIcon },
              { id: 'patches',         label: 'Patches',         icon: WrenchScrewdriverIcon },
            ] as const).map(tab => (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 ${
                  activeTab === tab.id
                    ? 'bg-white dark:bg-surface-800 text-gray-900 dark:text-white shadow-sm border border-gray-200/50 dark:border-white/[0.08]'
                    : 'text-gray-500 dark:text-surface-400 hover:text-gray-700 dark:hover:text-surface-200 border border-transparent hover:bg-white/50 dark:hover:bg-white/[0.02]'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
                {tab.id === 'vulnerabilities' && total > 0 && (
                  <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${
                    activeTab === tab.id ? 'bg-gray-100 dark:bg-surface-950 text-gray-700 dark:text-surface-200' : 'bg-gray-200/50 dark:bg-surface-800 text-gray-500 dark:text-surface-400'
                  }`}>
                    {total}
                  </span>
                )}
              </button>
            ))}
          </div>



          {/* ── Vulnerabilities tab ─────────────────── */}
          {activeTab === 'vulnerabilities' && (
            <div className="card overflow-hidden animate-fade-in">
              <div className="px-5 py-4 border-b border-white/[0.06] flex items-center gap-3">
                <ShieldExclamationIcon className="w-4 h-4 text-zinc-500" />
                <h3 className="text-sm font-semibold text-white">Detected Vulnerabilities</h3>
                <span className="px-2 py-0.5 rounded-full bg-white/10 text-xs font-bold text-zinc-300">{total}</span>
                <span className="ml-auto text-xs text-zinc-600">Click a row to expand details</span>
              </div>
              {total === 0 ? (
                <div className="p-12 text-center">
                  <CheckCircleIcon className="w-12 h-12 text-brand-500/40 mx-auto mb-3" />
                  <p className="text-sm text-zinc-500">No vulnerabilities detected</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-white/[0.06]">
                        {['ID', 'Type', 'Location', 'Severity', 'Status', 'Agent', 'Time'].map(h => (
                          <th key={h} className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-zinc-500">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {vulns.map(v => <VulnRow key={v.id} v={v} />)}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ── Patches tab ─────────────────────────── */}
          {activeTab === 'patches' && (
            <div className="animate-fade-in">
              {total === 0 ? (
                <div className="card p-12 text-center">
                  <WrenchScrewdriverIcon className="w-12 h-12 text-zinc-700 mx-auto mb-3" />
                  <p className="text-sm text-zinc-500">No patches to display</p>
                </div>
              ) : (
                <>
                  <div className="flex items-center gap-3 mb-4">
                    <WrenchScrewdriverIcon className="w-4 h-4 text-zinc-500" />
                    <h3 className="text-sm font-semibold text-white">Patch Analysis</h3>
                    <span className="text-xs text-zinc-600">Review patches and click <strong className="text-brand-400">Apply Patch</strong> to fix the source.</span>
                  </div>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {vulns.map(v => <PatchCard key={v.id} v={v} targetId={target.id} runId={runId} onPatchApplied={(vulnId) => {
                      setSummary(prev => prev ? {
                        ...prev,
                        vulnerabilities: (prev.vulnerabilities ?? []).map(x =>
                          x.id === vulnId ? { ...x, status: 'Resolved' } : x
                        ),
                        total_bugs_resolved: (prev.total_bugs_resolved ?? 0) + 1,
                      } : prev);
                    }} />)}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Back button ──────────────────────────────── */}
      {isDone && (
        <div className="flex justify-end animate-fade-in">
          <button onClick={onBack} className="btn-secondary gap-2">
            ← Analyze Another Target
          </button>
        </div>
      )}
    </div>
  );
}
