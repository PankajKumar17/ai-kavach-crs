import { useState, useEffect, useCallback } from 'react';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { fetchRunSummary, listTargets, TargetCodebase } from './api';
import { RunSummary } from './types';
import { TargetUpload } from './components/TargetUpload';
import { PipelineView } from './components/PipelineView';
import { RocketLaunchIcon, SunIcon, MoonIcon, ChevronLeftIcon, CloudIcon, CpuChipIcon } from '@heroicons/react/24/solid';
import { ShieldCheckIcon } from '@heroicons/react/24/outline';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1 },
  },
});

/* ─── Theme helpers ──────────────────────────────────── */
function getInitialDark(): boolean {
  try {
    const saved = localStorage.getItem('kavach-theme');
    if (saved !== null) return saved === 'dark';
  } catch (_) { /* ignore */ }
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function applyTheme(dark: boolean) {
  const root = document.documentElement;
  if (dark) root.classList.add('dark');
  else       root.classList.remove('dark');
}

/* ─── View types ─────────────────────────────────────── */
type AppView = 'upload' | 'dashboard' | 'pipeline';

/* ─── Dashboard ──────────────────────────────────────── */
function Dashboard() {
  const [runId, setRunId]     = useState<string | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<TargetCodebase | null>(null);
  const [targets, setTargets]               = useState<TargetCodebase[]>([]);
  const [view, setView]   = useState<AppView>('upload');
  const [llmMode, setLlmMode] = useState<'online' | 'local'>('online');
  const [isDark, setIsDark] = useState<boolean>(() => {
    const initial = getInitialDark();
    applyTheme(initial);
    return initial;
  });

  // Sync theme
  useEffect(() => {
    applyTheme(isDark);
    try { localStorage.setItem('kavach-theme', isDark ? 'dark' : 'light'); } catch (_) { /* ignore */ }
  }, [isDark]);

  const toggleTheme = useCallback(() => setIsDark(d => !d), []);

  const { data: summary, isLoading } = useQuery<RunSummary>({
    queryKey: ['runSummary', runId],
    queryFn: () => fetchRunSummary(runId!),
    enabled: view === 'dashboard' && !!runId,
  });

  useEffect(() => {
    listTargets().then(setTargets).catch(console.error);
  }, []);

  const handleTargetCreated = (target: TargetCodebase) => {
    setTargets(prev => [...prev, target]);
    setSelectedTarget(target);
    setView('dashboard');
  };

  const handleSelectExisting = (target: TargetCodebase) => {
    setSelectedTarget(target);
    setRunId(null); // Clear previous runId when selecting a different target from history
    setView('dashboard');
  };

  const handleStartAnalysis = () => {
    if (selectedTarget) {
      // Generate a unique run_id per target per scan so results never bleed between analyses
      const ts = Date.now();
      const newRunId = `${selectedTarget.id.replace(/[^a-z0-9]/gi, '_').slice(0, 24)}_${ts}`;
      setRunId(newRunId);
      setView('pipeline');
    }
  };

  const handlePipelineBack = () => {
    // After pipeline completes, go back to dashboard (which will refetch)
    queryClient.invalidateQueries({ queryKey: ['runSummary', runId] });
    setView('dashboard');
  };

  /* ─────────────────────────────────────────────────── */
  return (
    <div className="min-h-screen transition-colors duration-300">

      {/* ── Header ──────────────────────────────────── */}
      <header className="sticky top-0 z-50 glass border-b border-gray-200 dark:border-white/[0.04]">
        <div className="max-w-screen-xl mx-auto px-6 h-16 flex items-center justify-between gap-4">

          {/* Logo */}
          <div className="flex items-center gap-3.5 min-w-0">
            <div className="flex-shrink-0 w-9 h-9 rounded-xl bg-gradient-to-br from-brand-400 to-brand-600 shadow-lg shadow-brand-500/20 flex items-center justify-center">
              <ShieldCheckIcon className="w-5 h-5 text-white" />
            </div>
            <div className="min-w-0 flex flex-col justify-center">
              <span className="font-bold text-[17px] text-gray-900 dark:text-white leading-tight">AI Kavach</span>
            </div>
          </div>

          {/* Right controls */}
          <div className="flex items-center gap-3 flex-shrink-0">

            {/* Back to targets */}
            {(view === 'dashboard' || view === 'pipeline') && (
              <button
                onClick={() => setView('upload')}
                className="btn-secondary text-[13px] gap-1.5 !px-4 !py-2"
              >
                <ChevronLeftIcon className="w-3.5 h-3.5" />
                Change Target
              </button>
            )}

            {/* Start Analysis — only on dashboard view */}
            {view === 'dashboard' && selectedTarget && (
              <button
                id="start-analysis-btn"
                onClick={handleStartAnalysis}
                className="btn-primary !px-5 !py-2"
              >
                <RocketLaunchIcon className="w-4 h-4" />
                Start Analysis
              </button>
            )}

            {/* LLM Mode Toggle */}
            {view !== 'pipeline' && (
              <div className="flex bg-gray-100 dark:bg-surface-800 p-1 rounded-xl border border-gray-200 dark:border-white/[0.04]">
                <button
                  onClick={() => setLlmMode('online')}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-[13px] font-medium transition-all ${
                    llmMode === 'online'
                      ? 'bg-white dark:bg-surface-600 text-brand-600 dark:text-brand-400 shadow-sm'
                      : 'text-gray-500 dark:text-surface-400 hover:text-gray-900 dark:hover:text-surface-200'
                  }`}
                >
                  <CloudIcon className="w-4 h-4" />
                  Online LLM
                </button>
                <button
                  onClick={() => setLlmMode('local')}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-[13px] font-medium transition-all ${
                    llmMode === 'local'
                      ? 'bg-white dark:bg-surface-600 text-brand-600 dark:text-brand-400 shadow-sm'
                      : 'text-gray-500 dark:text-surface-400 hover:text-gray-900 dark:hover:text-surface-200'
                  }`}
                >
                  <CpuChipIcon className="w-4 h-4" />
                  Local LLM
                </button>
              </div>
            )}

            {/* Theme toggle */}
            <button
              id="theme-toggle-btn"
              onClick={toggleTheme}
              aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              className="w-9 h-9 rounded-full flex items-center justify-center border border-gray-200 dark:border-white/[0.08] bg-white dark:bg-surface-800 hover:bg-gray-50 dark:hover:bg-surface-700 text-gray-600 dark:text-surface-300 transition-all duration-200 hover:scale-105"
            >
              {isDark
                ? <SunIcon className="w-4 h-4" />
                : <MoonIcon className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </header>

      {/* ── Main ──────────────────────────────────────── */}
      <main className="max-w-screen-xl mx-auto px-4 sm:px-6 py-10">

        {/* ── Pipeline view ─────────────────────────── */}
        {view === 'pipeline' && selectedTarget ? (
          <PipelineView
            target={selectedTarget}
            runId={runId!}
            onBack={handlePipelineBack}
          />

        /* ── Upload / Target Selection ──────────────── */
        ) : view === 'upload' ? (
          <div className="animate-fade-in space-y-8 max-w-4xl mx-auto">
            <TargetUpload onTargetCreated={handleTargetCreated} />

            {targets.length > 0 && (
              <div className="card p-0 animate-slide-up overflow-hidden">
                <div className="bg-gray-50/50 dark:bg-white/[0.02] px-6 py-4 border-b border-gray-100 dark:border-white/[0.04]">
                  <h3 className="text-sm font-semibold text-gray-800 dark:text-surface-200">
                    Recent Targets
                  </h3>
                </div>
                <div className="divide-y divide-gray-100 dark:divide-white/[0.04]">
                  {targets.slice(-5).reverse().map(target => (
                    <button
                      key={target.id}
                      id={`target-${target.id}`}
                      onClick={() => handleSelectExisting(target)}
                      className="w-full flex items-center gap-5 p-5 bg-white dark:bg-transparent hover:bg-gray-50/80 dark:hover:bg-white/[0.02] text-left transition-all duration-200 group"
                    >
                      <div className="w-10 h-10 rounded-xl bg-brand-50 dark:bg-brand-500/10 flex items-center justify-center flex-shrink-0 group-hover:scale-105 transition-transform">
                        <span className="text-[11px] font-mono font-bold text-brand-600 dark:text-brand-400">
                          {target.source_type === 'github' ? 'GIT' : 'ZIP'}
                        </span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-gray-900 dark:text-white truncate">{target.name}</p>
                        <p className="text-xs text-gray-500 dark:text-surface-400 mt-0.5 flex items-center gap-2">
                          {target.source_type === 'github' ? 'GitHub' : 'ZIP file'}
                          <span className="w-1 h-1 rounded-full bg-gray-300 dark:bg-surface-600" />
                          <span className={`font-medium ${target.status === 'ready' ? 'text-brand-600 dark:text-brand-400' : 'text-gray-400'}`}>
                            {target.status}
                          </span>
                        </p>
                      </div>
                      <div className="w-8 h-8 rounded-full bg-white dark:bg-surface-800 border border-gray-100 dark:border-white/[0.05] flex items-center justify-center opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-300 shadow-sm">
                        <RocketLaunchIcon className="w-3.5 h-3.5 text-brand-500" />
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

        /* ── Dashboard ──────────────────────────────── */
        ) : isLoading ? (
          <div className="flex flex-col items-center justify-center py-32 animate-fade-in">
            <div className="w-10 h-10 border-2 border-gray-200 dark:border-white/10 border-t-brand-500 rounded-full animate-spin mb-4" />
            <p className="text-sm text-gray-500 dark:text-surface-400">Loading analysis data…</p>
          </div>

        ) : summary && selectedTarget && runId ? (
          <div className="space-y-6 animate-fade-in max-w-6xl mx-auto">
            <PipelineView 
              target={selectedTarget}
              runId={runId}
              onBack={() => setView('upload')}
              onReanalyze={handleStartAnalysis}
              initialSummary={summary}
            />
          </div>

        ) : (
          <div className="card p-16 text-center animate-fade-in border-dashed border-2 border-gray-200 dark:border-white/[0.05] bg-gray-50/50 dark:bg-transparent shadow-none max-w-3xl mx-auto">
            <div className="w-16 h-16 rounded-2xl bg-white dark:bg-surface-800 border border-gray-200 dark:border-white/[0.08] shadow-sm flex items-center justify-center mx-auto mb-5">
              <ShieldCheckIcon className="w-8 h-8 text-gray-400 dark:text-surface-400" />
            </div>
            <h3 className="text-base font-semibold text-gray-900 dark:text-white mb-2">No Analysis Data</h3>
            <p className="text-sm text-gray-500 dark:text-surface-400">
              Select a target and click <strong className="text-brand-600 dark:text-brand-400 font-semibold">Start Analysis</strong>.
            </p>
            {selectedTarget && (
              <button onClick={handleStartAnalysis} className="btn-primary mt-6 mx-auto">
                <RocketLaunchIcon className="w-4 h-4" />
                Start Analysis
              </button>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

/* ─── Root ───────────────────────────────────────────── */
export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Dashboard />
    </QueryClientProvider>
  );
}
