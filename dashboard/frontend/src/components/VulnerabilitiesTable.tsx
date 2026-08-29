import { Vulnerability } from '../types';
import { useState } from 'react';
import {
  ShieldExclamationIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ArrowsUpDownIcon,
  FunnelIcon,
} from '@heroicons/react/24/outline';

interface VulnerabilitiesTableProps {
  vulnerabilities: Vulnerability[];
}

/* ─── Config ─────────────────────────────────────────── */
const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'severity-critical',
  HIGH:     'severity-high',
  MEDIUM:   'severity-medium',
  LOW:      'severity-low',
};

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH:     'bg-orange-500',
  MEDIUM:   'bg-yellow-500',
  LOW:      'bg-brand-500',
};

const STATUS_STYLES: Record<string, string> = {
  'Resolved':        'status-resolved',
  'Failed':          'status-failed',
  'Failed (Timeout)':'status-failed',
  'Pending':         'status-pending',
};

const STATUS_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  'Resolved':        CheckCircleIcon,
  'Failed':          XCircleIcon,
  'Failed (Timeout)':XCircleIcon,
  'Pending':         ClockIcon,
};

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

type SortKey = 'severity' | 'status' | 'time';
const SORT_LABELS: SortKey[] = ['severity', 'status', 'time'];

/* ─── Component ──────────────────────────────────────── */
export function VulnerabilitiesTable({ vulnerabilities }: VulnerabilitiesTableProps) {
  const [sortBy, setSortBy]           = useState<SortKey>('severity');
  const [filterSeverity, setFilter]   = useState('all');

  let rows = [...vulnerabilities];

  if (filterSeverity !== 'all') {
    rows = rows.filter(v => v.severity === filterSeverity);
  }

  rows.sort((a, b) => {
    if (sortBy === 'severity') return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sortBy === 'status')   return a.status.localeCompare(b.status);
    return parseFloat(a.time_taken) - parseFloat(b.time_taken);
  });

  /* ── Empty state ──────────────────────────────────── */
  if (vulnerabilities.length === 0) {
    return (
      <div className="card p-12 text-center">
        <ShieldExclamationIcon className="w-12 h-12 text-gray-300 dark:text-zinc-700 mx-auto mb-4" />
        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-1">No Vulnerabilities Detected</h3>
        <p className="text-sm text-gray-500 dark:text-zinc-500">Run the pipeline to discover and analyze vulnerabilities</p>
      </div>
    );
  }

  /* ── Table ────────────────────────────────────────── */
  return (
    <div className="card overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-gray-100 dark:border-white/[0.06] flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2.5">
          <ShieldExclamationIcon className="w-4 h-4 text-gray-500 dark:text-zinc-500" />
          <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Detected Vulnerabilities</h2>
          <span className="badge bg-gray-100 dark:bg-white/10 text-gray-600 dark:text-zinc-400 text-[11px]">
            {vulnerabilities.length}
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Filter */}
          <div className="flex items-center gap-1.5">
            <FunnelIcon className="w-3.5 h-3.5 text-gray-400 dark:text-zinc-500" />
            <select
              id="severity-filter"
              value={filterSeverity}
              onChange={e => setFilter(e.target.value)}
              className="text-xs px-2.5 py-1.5 rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-white/5 text-gray-700 dark:text-zinc-300 focus:outline-none focus:ring-2 focus:ring-brand-500/40 transition-all"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Sort */}
          <div className="flex items-center gap-1.5">
            <ArrowsUpDownIcon className="w-3.5 h-3.5 text-gray-400 dark:text-zinc-500" />
            <div className="flex rounded-lg border border-gray-200 dark:border-white/10 overflow-hidden text-xs bg-white dark:bg-white/5">
              {SORT_LABELS.map(key => (
                <button
                  key={key}
                  id={`sort-${key}-btn`}
                  onClick={() => setSortBy(key)}
                  className={`px-3 py-1.5 capitalize font-medium transition-colors ${
                    sortBy === key
                      ? 'bg-gray-900 dark:bg-white text-white dark:text-gray-900'
                      : 'text-gray-600 dark:text-zinc-400 hover:bg-gray-50 dark:hover:bg-white/5'
                  }`}
                >
                  {key}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-100 dark:border-white/[0.06]">
              <th className="table-header-cell">ID</th>
              <th className="table-header-cell">Type</th>
              <th className="table-header-cell">Location</th>
              <th className="table-header-cell">Severity</th>
              <th className="table-header-cell">Status</th>
              <th className="table-header-cell">Agent</th>
              <th className="table-header-cell text-right">Time</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(vuln => {
              const StatusIcon  = STATUS_ICONS[vuln.status] ?? ClockIcon;
              const statusStyle = STATUS_STYLES[vuln.status] ?? 'status-pending';
              const sevStyle    = SEVERITY_STYLES[vuln.severity] ?? 'severity-low';
              const sevDot      = SEVERITY_DOT[vuln.severity] ?? 'bg-gray-400';

              return (
                <tr key={vuln.id} className="table-row">
                  <td className="table-cell">
                    <code className="font-mono text-xs text-brand-600 dark:text-brand-400 font-medium">
                      {vuln.id}
                    </code>
                  </td>
                  <td className="table-cell font-medium text-gray-900 dark:text-white">
                    {vuln.type}
                  </td>
                  <td className="table-cell">
                    <code className="font-mono text-xs text-gray-500 dark:text-zinc-500">
                      {vuln.location}
                    </code>
                  </td>
                  <td className="table-cell">
                    <span className={sevStyle}>
                      <span className={`w-1.5 h-1.5 rounded-full ${sevDot} flex-shrink-0`} />
                      {vuln.severity}
                    </span>
                  </td>
                  <td className="table-cell">
                    <span className={statusStyle}>
                      <StatusIcon className="w-3.5 h-3.5 flex-shrink-0" />
                      {vuln.status}
                    </span>
                  </td>
                  <td className="table-cell text-gray-500 dark:text-zinc-500">
                    {vuln.agent}
                  </td>
                  <td className="table-cell text-right">
                    <code className="font-mono text-xs text-gray-600 dark:text-zinc-400">
                      {vuln.time_taken}
                    </code>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="px-5 py-3 border-t border-gray-100 dark:border-white/[0.06] flex items-center justify-between">
        <p className="text-xs text-gray-400 dark:text-zinc-600">
          Showing {rows.length} of {vulnerabilities.length} vulnerabilities
        </p>
        <div className="flex items-center gap-3 text-xs text-gray-400 dark:text-zinc-600">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Critical</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> High</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-500" /> Medium</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-brand-500" /> Low</span>
        </div>
      </div>
    </div>
  );
}