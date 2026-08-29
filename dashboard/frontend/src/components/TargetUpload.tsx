import { useState } from 'react';
import { TargetCodebase } from '../types';
import { uploadTargetZip, createTargetGithub } from '../api';
import { ArrowUpTrayIcon, PlusIcon, ArrowPathIcon } from '@heroicons/react/24/outline';

interface TargetUploadProps {
  onTargetCreated: (target: TargetCodebase) => void;
  authToken?: string;
}

type UploadMode = 'github' | 'zip';

export function TargetUpload({ onTargetCreated, authToken }: TargetUploadProps) {
  const [mode, setMode]             = useState<UploadMode>('github');
  const [name, setName]             = useState('');
  const [githubUrl, setGithubUrl]   = useState('');
  const [branch, setBranch]         = useState('main');
  const [zipFile, setZipFile]       = useState<File | null>(null);
  const [uploading, setUploading]   = useState(false);
  const [error, setError]           = useState<string | null>(null);
  const [dragOver, setDragOver]     = useState(false);

  /* ─── Handlers ──────────────────────────────────── */
  const handleFileSelect = (file: File | undefined) => {
    if (!file) return;
    if (!file.name.endsWith('.zip')) {
      setError('Only .zip files are supported');
      return;
    }
    setZipFile(file);
    setError(null);
    if (!name) setName(file.name.replace(/\.zip$/i, ''));
  };

  const handleDrop = (e: React.DragEvent<HTMLLabelElement>) => {
    e.preventDefault();
    setDragOver(false);
    handleFileSelect(e.dataTransfer.files[0]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setUploading(true);

    try {
      let target: TargetCodebase;

      if (mode === 'zip') {
        if (!zipFile) { setError('Please select a ZIP file'); setUploading(false); return; }
        target = await uploadTargetZip(name || zipFile.name.replace(/\.zip$/i, ''), zipFile, authToken);
      } else {
        const url = githubUrl.trim();
        if (!url) { setError('Please enter a repository URL'); setUploading(false); return; }
        target = await createTargetGithub(
          name || url.split('/').pop() || 'Repository',
          url, branch, authToken
        );
      }

      onTargetCreated(target);
      // reset
      setName(''); setGithubUrl(''); setBranch('main'); setZipFile(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  const canSubmit = !uploading &&
    (mode === 'github' ? githubUrl.trim().length > 0 : zipFile !== null);

  /* ─── Render ────────────────────────────────────── */
  return (
    <div className="card overflow-hidden animate-slide-up shadow-sm">
      {/* Header */}
      <div className="px-8 pt-7 pb-5 border-b border-gray-100 dark:border-white/[0.04] bg-white dark:bg-transparent">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white tracking-tight">New Target</h2>
        <p className="text-[13px] text-gray-500 dark:text-surface-400 mt-1">Connect a repository or upload a ZIP file.</p>
      </div>

      <form onSubmit={handleSubmit} className="p-8 space-y-6">
        {/* ── Mode tabs ─────────────────────────────── */}
        <div className="flex p-1 bg-gray-50 dark:bg-surface-900/50 rounded-xl border border-gray-100 dark:border-white/[0.04]">
          <button
            type="button"
            id="tab-github"
            onClick={() => setMode('github')}
            className={`flex-1 py-2.5 px-4 text-[13px] font-medium rounded-lg transition-all duration-200 ${
              mode === 'github'
                ? 'text-brand-700 dark:text-brand-300 bg-white dark:bg-surface-800 shadow-sm border border-gray-200 dark:border-white/[0.08]'
                : 'text-gray-500 dark:text-surface-400 hover:text-gray-700 dark:hover:text-surface-200 border border-transparent'
            }`}
          >
            <span className="flex items-center justify-center gap-2">
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
              </svg>
              GitHub Repository
            </span>
          </button>
          <button
            type="button"
            id="tab-zip"
            onClick={() => setMode('zip')}
            className={`flex-1 py-2.5 px-4 text-[13px] font-medium rounded-lg transition-all duration-200 ${
              mode === 'zip'
                ? 'text-brand-700 dark:text-brand-300 bg-white dark:bg-surface-800 shadow-sm border border-gray-200 dark:border-white/[0.08]'
                : 'text-gray-500 dark:text-surface-400 hover:text-gray-700 dark:hover:text-surface-200 border border-transparent'
            }`}
          >
            <span className="flex items-center justify-center gap-2">
              <ArrowUpTrayIcon className="w-4 h-4" />
              Upload ZIP
            </span>
          </button>
        </div>

        {/* ── GitHub fields ─────────────────────────── */}
        {mode === 'github' && (
          <div className="space-y-4 animate-fade-in">
            <div>
              <label htmlFor="github-url" className="block text-xs font-semibold text-gray-700 dark:text-surface-300 mb-1.5">
                Repository URL <span className="text-brand-500">*</span>
              </label>
              <input
                id="github-url"
                type="url"
                value={githubUrl}
                onChange={e => setGithubUrl(e.target.value)}
                placeholder="https://github.com/username/repository"
                className="input"
                required
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label htmlFor="repo-name" className="block text-xs font-semibold text-gray-700 dark:text-surface-300 mb-1.5">
                  Display name <span className="text-gray-400 dark:text-surface-500 font-normal ml-1">(Optional)</span>
                </label>
                <input
                  id="repo-name"
                  type="text"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="Auto-detected"
                  className="input"
                />
              </div>
              <div>
                <label htmlFor="git-branch" className="block text-xs font-semibold text-gray-700 dark:text-surface-300 mb-1.5">
                  Branch
                </label>
                <input
                  id="git-branch"
                  type="text"
                  value={branch}
                  onChange={e => setBranch(e.target.value)}
                  placeholder="main"
                  className="input"
                />
              </div>
            </div>
          </div>
        )}

        {/* ── ZIP upload ────────────────────────────── */}
        {mode === 'zip' && (
          <div className="space-y-4 animate-fade-in">
            <div>
              <p className="block text-xs font-semibold text-gray-700 dark:text-surface-300 mb-1.5">
                ZIP Archive <span className="text-brand-500">*</span>
              </p>
              {/* Hidden file input */}
              <input
                id="zip-file-input"
                type="file"
                accept=".zip"
                className="sr-only"
                onChange={e => handleFileSelect(e.target.files?.[0])}
              />
              {/* Drop zone label */}
              <label
                htmlFor="zip-file-input"
                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                className={`flex flex-col items-center justify-center w-full min-h-[160px] border-2 border-dashed cursor-pointer rounded-2xl transition-all duration-300 ${
                  dragOver
                    ? 'border-brand-500 bg-brand-50 dark:bg-brand-500/10 scale-[1.01]'
                    : zipFile
                    ? 'border-brand-500/30 bg-brand-50/50 dark:bg-brand-500/5'
                    : 'border-gray-300 dark:border-white/[0.1] hover:border-brand-400 dark:hover:border-brand-500/50 hover:bg-gray-50 dark:hover:bg-surface-900'
                }`}
              >
                {zipFile ? (
                  <div className="text-center px-4 py-6 animate-scale-in">
                    <div className="w-12 h-12 rounded-xl border border-brand-200 dark:border-brand-500/20 bg-brand-100 dark:bg-brand-500/10 flex items-center justify-center mx-auto mb-3">
                      <ArrowUpTrayIcon className="w-6 h-6 text-brand-600 dark:text-brand-400" />
                    </div>
                    <p className="text-sm font-semibold text-gray-900 dark:text-white">{zipFile.name}</p>
                    <p className="text-xs text-gray-500 dark:text-surface-400 mt-1">
                      {(zipFile.size / 1024 / 1024).toFixed(2)} MB <span className="mx-2">•</span> Click to change
                    </p>
                  </div>
                ) : (
                  <div className="text-center px-4 py-6">
                    <div className="w-12 h-12 rounded-xl border border-gray-200 dark:border-white/[0.08] bg-white dark:bg-surface-800 shadow-sm flex items-center justify-center mx-auto mb-3">
                      <ArrowUpTrayIcon className="w-6 h-6 text-gray-400 dark:text-surface-400" />
                    </div>
                    <p className="text-sm font-semibold text-gray-800 dark:text-surface-200">
                      Drag & drop your payload or <span className="text-brand-600 dark:text-brand-400 underline decoration-brand-500/30 underline-offset-4">browse</span>
                    </p>
                    <p className="text-[11px] text-gray-500 dark:text-surface-500 mt-1.5">Max file size: 100 MB (.zip)</p>
                  </div>
                )}
              </label>
            </div>

            {zipFile && (
              <div className="animate-fade-in">
                <label htmlFor="zip-name" className="block text-xs font-semibold text-gray-700 dark:text-surface-300 mb-1.5">
                  Display name <span className="text-gray-400 dark:text-surface-500 ml-1 font-normal">(Optional)</span>
                </label>
                <input
                  id="zip-name"
                  type="text"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="Auto-detected from filename"
                  className="input"
                />
              </div>
            )}
          </div>
        )}

        {/* ── Error ─────────────────────────────────── */}
        {error && (
          <div className="p-4 rounded-xl border border-red-200 dark:border-red-500/20 bg-red-50 dark:bg-red-500/10 text-sm text-red-600 dark:text-red-400 animate-slide-up flex items-center gap-3">
            <span className="font-semibold text-red-700 dark:text-red-300">Error:</span> {error}
          </div>
        )}

        {/* ── Submit ────────────────────────────────── */}
        <button
          id="upload-submit-btn"
          type="submit"
          disabled={!canSubmit}
          className="btn-primary w-full justify-center py-3 text-[15px]"
        >
          {uploading ? (
            <>
              <ArrowPathIcon className="w-5 h-5 animate-spin" />
              {mode === 'github' ? 'Connecting to GitHub…' : 'Uploading Payload…'}
            </>
          ) : (
            <>
              <PlusIcon className="w-5 h-5" />
              {mode === 'github' ? 'Add Repository' : 'Upload ZIP'}
            </>
          )}
        </button>
      </form>
    </div>
  );
}
