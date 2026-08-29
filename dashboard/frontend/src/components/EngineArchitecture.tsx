import { useEffect, useState } from 'react';
import {
  FolderIcon, MagnifyingGlassIcon, CpuChipIcon, BeakerIcon,
  WrenchScrewdriverIcon, FunnelIcon, BugAntIcon, CheckBadgeIcon,
  ShieldCheckIcon, CodeBracketIcon, WrenchIcon, ArrowsPointingOutIcon,
  ChartBarIcon, ClockIcon, BoltIcon,
} from '@heroicons/react/24/outline';
import { CheckCircleIcon } from '@heroicons/react/24/solid';

interface Module {
  id: string;
  name: string;
  icon: string;
  phase: number;
  status: 'active' | 'available' | 'unavailable';
  description: string;
  file: string;
  metrics: Record<string, string> | null;
}

interface ModulesData {
  provider: string;
  model: string;
  modules: Module[];
}

const ICON_MAP: Record<string, React.FC<{ className?: string }>> = {
  'folder':             FolderIcon,
  'magnifying-glass':   MagnifyingGlassIcon,
  'cpu-chip':           CpuChipIcon,
  'beaker':             BeakerIcon,
  'wrench-screwdriver': WrenchScrewdriverIcon,
  'funnel':             FunnelIcon,
  'bug-ant':            BugAntIcon,
  'check-badge':        CheckBadgeIcon,
  'shield-check':       ShieldCheckIcon,
  'code-bracket':       CodeBracketIcon,
  'wrench':             WrenchIcon,
  'arrows-pointing-out':ArrowsPointingOutIcon,
  'chart-bar':          ChartBarIcon,
  'clock':              ClockIcon,
};

const STATUS_CFG = {
  active:      { dot: 'bg-emerald-400', label: 'Active',      badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20', glow: 'shadow-[0_0_12px_rgba(52,211,153,0.12)]' },
  available:   { dot: 'bg-amber-400',   label: 'Available',   badge: 'bg-amber-500/10  text-amber-400  border-amber-500/20',  glow: '' },
  unavailable: { dot: 'bg-zinc-600',    label: 'Unavailable', badge: 'bg-zinc-700/50   text-zinc-500   border-zinc-600/20',   glow: '' },
};

const PHASE_LABELS: Record<number, string> = {
  0: 'Infrastructure',
  1: 'Phase 1  ·  Discovery & Instrumentation',
  2: 'Phase 2  ·  Analysis & Fuzzing',
  3: 'Phase 3  ·  LLM Reasoning',
  4: 'Phase 4  ·  Patching & Verification',
  5: 'Phase 5  ·  Reporting',
};

function ModuleCard({ m }: { m: Module }) {
  const Icon = ICON_MAP[m.icon] ?? BoltIcon;
  const s    = STATUS_CFG[m.status];
  return (
    <div className={`group relative rounded-xl border border-white/[0.07] bg-white/[0.02] p-4 hover:bg-white/[0.05] transition-all duration-200 ${s.glow}`}>
      {m.status === 'active' && (
        <span className="absolute top-3 right-3 flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-50" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
        </span>
      )}
      <div className="flex items-start gap-3 mb-3">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${m.status === 'active' ? 'bg-brand-500/15' : 'bg-white/[0.04]'}`}>
          <Icon className={`w-5 h-5 ${m.status === 'active' ? 'text-brand-400' : 'text-zinc-500'}`} />
        </div>
        <div className="min-w-0 flex-1">
          <p className={`text-sm font-semibold leading-tight ${m.status === 'active' ? 'text-white' : 'text-zinc-300'}`}>{m.name}</p>
          <code className="text-[10px] text-zinc-600 font-mono mt-0.5 block truncate">{m.file}</code>
        </div>
      </div>
      <p className="text-[12px] text-zinc-500 leading-relaxed mb-3 line-clamp-3 group-hover:line-clamp-none">{m.description}</p>
      {m.metrics && (
        <div className="space-y-1 mb-3 border-t border-white/[0.05] pt-2">
          {Object.entries(m.metrics).map(([k, v]) => (
            <div key={k} className="flex items-center justify-between gap-2">
              <span className="text-[10px] text-zinc-600 font-mono uppercase tracking-wider">{k.replace(/_/g, ' ')}</span>
              <span className={`text-[11px] font-mono ${v.startsWith('✓') ? 'text-emerald-400' : v.startsWith('✗') ? 'text-red-400' : 'text-zinc-300'}`}>{v}</span>
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center gap-1.5">
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${s.badge}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
          {s.label}
        </span>
        {m.phase > 0 && <span className="text-[10px] text-zinc-700 font-mono">Phase {m.phase}</span>}
      </div>
    </div>
  );
}

export function EngineArchitecture() {
  const [data, setData]       = useState<ModulesData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');

  useEffect(() => {
    fetch('/api/engine/modules')
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, []);

  if (loading) return (
    <div className="flex items-center justify-center py-20">
      <div className="w-8 h-8 border-2 border-white/10 border-t-brand-500 rounded-full animate-spin" />
    </div>
  );

  if (error || !data) return (
    <div className="card p-8 text-center">
      <p className="text-sm text-red-400">Failed to load engine modules: {error}</p>
    </div>
  );

  const phases: Record<number, Module[]> = {};
  for (const m of data.modules) {
    if (!phases[m.phase]) phases[m.phase] = [];
    phases[m.phase].push(m);
  }

  const activeCount  = data.modules.filter(m => m.status === 'active').length;
  const availCount   = data.modules.filter(m => m.status === 'available').length;
  const unavailCount = data.modules.filter(m => m.status === 'unavailable').length;

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Modules', value: data.modules.length, color: 'text-white' },
          { label: 'Active',        value: activeCount,          color: 'text-emerald-400' },
          { label: 'Available',     value: availCount,           color: 'text-amber-400' },
          { label: 'Unavailable',   value: unavailCount,         color: 'text-zinc-500' },
        ].map(s => (
          <div key={s.label} className="card p-4 text-center">
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            <p className="text-[11px] text-zinc-500 mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-brand-500/20 bg-brand-500/5 px-5 py-4 flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <CpuChipIcon className="w-5 h-5 text-brand-400 flex-shrink-0" />
          <span className="text-sm font-semibold text-white">Active LLM</span>
        </div>
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <span className="px-2 py-0.5 rounded-md bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-mono">{data.provider.toUpperCase()}</span>
          <span className="text-sm text-zinc-300 font-mono truncate">{data.model}</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-zinc-400">
          <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
          Multi-provider · Auto-fallback enabled
        </div>
      </div>

      {Object.entries(phases)
        .sort(([a], [b]) => parseInt(a) - parseInt(b))
        .map(([phase, modules]) => (
          <div key={phase} className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="h-px flex-1 bg-white/[0.06]" />
              <span className="text-[11px] font-semibold uppercase tracking-widest text-zinc-500 whitespace-nowrap">
                {PHASE_LABELS[parseInt(phase)] ?? `Phase ${phase}`}
              </span>
              <div className="h-px flex-1 bg-white/[0.06]" />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {modules.map(m => <ModuleCard key={m.id} m={m} />)}
            </div>
          </div>
        ))}

      <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-white/[0.05]">
        <span className="text-[11px] text-zinc-600">Legend:</span>
        {(Object.entries(STATUS_CFG) as [string, typeof STATUS_CFG.active][]).map(([key, s]) => (
          <div key={key} className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${s.dot}`} />
            <span className="text-[11px] text-zinc-500">{s.label}</span>
          </div>
        ))}
        <span className="text-[11px] text-zinc-600 ml-auto">Hover a card to expand description</span>
      </div>
    </div>
  );
}
