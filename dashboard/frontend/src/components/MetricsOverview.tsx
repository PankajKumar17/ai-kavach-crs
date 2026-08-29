import { RunSummary } from '../types';
import { CheckCircleIcon, ClockIcon, CpuChipIcon } from '@heroicons/react/24/outline';

/* ─── Types ─────────────────────────────────────────── */
interface MetricCardProps {
  title: string;
  value: string;
  subtitle: string;
  icon: React.ComponentType<{ className?: string }>;
  accent: 'green' | 'blue' | 'violet' | 'amber';
}

const accentMap = {
  green:  { dot: 'bg-brand-500',  value: 'text-brand-600 dark:text-brand-400' },
  blue:   { dot: 'bg-blue-500',   value: 'text-blue-600  dark:text-blue-400'  },
  violet: { dot: 'bg-violet-500', value: 'text-violet-600 dark:text-violet-400' },
  amber:  { dot: 'bg-amber-500',  value: 'text-amber-600 dark:text-amber-400' },
};

/* ─── Metric Card ────────────────────────────────────── */
function MetricCard({ title, value, subtitle, icon: Icon, accent }: MetricCardProps) {
  const { value: valueColor } = accentMap[accent];

  return (
    <div className="card p-5 flex flex-col gap-4 hover:shadow-md dark:hover:shadow-black/20 transition-shadow">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-widest text-gray-500 dark:text-zinc-500">
          {title}
        </p>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center opacity-90
          ${accent === 'green'  ? 'bg-brand-500/10' :
            accent === 'blue'   ? 'bg-blue-500/10'  :
            accent === 'violet' ? 'bg-violet-500/10':
                                  'bg-amber-500/10'}`}>
          <Icon className={`w-4 h-4 ${valueColor}`} />
        </div>
      </div>

      {/* Value */}
      <div>
        <p className={`text-3xl font-bold tracking-tight ${valueColor}`}>{value}</p>
        <p className="text-xs text-gray-500 dark:text-zinc-500 mt-1">{subtitle}</p>
      </div>
    </div>
  );
}

/* ─── Metrics Overview ───────────────────────────────── */
interface MetricsOverviewProps {
  summary: RunSummary;
}

export function MetricsOverview({ summary }: MetricsOverviewProps) {
  const total    = summary.total_bugs_processed || 0;
  const resolved = summary.total_bugs_resolved  || 0;
  const rate     = total > 0 ? ((resolved / total) * 100).toFixed(1) : '0.0';
  const mttd     = summary.average_time_per_verified_patch_s
    ? (summary.average_time_per_verified_patch_s / 2).toFixed(1)
    : '0.0';
  const mttr     = summary.average_time_per_verified_patch_s
    ? summary.average_time_per_verified_patch_s.toFixed(1)
    : '0.0';
  const efficiency = (summary.percent_resolved_without_llm ?? 0).toFixed(0);

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      <MetricCard
        title="Success Rate"
        value={`${rate}%`}
        subtitle={`${resolved}/${total} bugs resolved`}
        icon={CheckCircleIcon}
        accent="green"
      />
      <MetricCard
        title="MTTD"
        value={`${mttd}s`}
        subtitle="Mean Time To Detect"
        icon={ClockIcon}
        accent="blue"
      />
      <MetricCard
        title="MTTR"
        value={`${mttr}s`}
        subtitle="Mean Time To Repair"
        icon={ClockIcon}
        accent="violet"
      />
      <MetricCard
        title="AI Efficiency"
        value={`${efficiency}%`}
        subtitle="Resolved via templates"
        icon={CpuChipIcon}
        accent="amber"
      />
    </div>
  );
}