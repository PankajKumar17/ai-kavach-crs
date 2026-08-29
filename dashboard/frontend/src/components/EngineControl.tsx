import { useState } from 'react';
import { PlayIcon, BeakerIcon, KeyIcon, SparklesIcon } from '@heroicons/react/24/solid';
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';

interface EngineControlProps {
  onStart: (authToken?: string) => void;
  onDemo: (authToken?: string) => void;
  isRunning: boolean;
}

export function EngineControl({ onStart, onDemo, isRunning }: EngineControlProps) {
  const [authToken, setAuthToken] = useState('');
  const [showTokenInput, setShowTokenInput] = useState(false);

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      <div className="bg-gradient-to-r from-army-500 to-army-600 px-6 py-4">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          <SparklesIcon className="w-5 h-5" />
          Engine Control
        </h3>
        <p className="text-army-50 text-sm mt-1">
          Trigger autonomous vulnerability detection and patching pipeline
        </p>
      </div>

      <div className="p-6">
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-6 flex items-start gap-3">
          <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-amber-800">
            <p className="font-medium mb-1">Real Pipeline Execution</p>
            <p>The engine will analyze target codebase, generate patches using Claude API, and verify fixes. This may take 1-2 minutes.</p>
          </div>
        </div>

        {showTokenInput && (
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
              <KeyIcon className="w-4 h-4" />
              Auth Token (optional for localhost)
            </label>
            <input
              type="password"
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              placeholder="Enter ENGINE_AUTH_TOKEN"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-army-500 focus:border-transparent font-mono text-sm"
            />
          </div>
        )}

        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => onStart(authToken || undefined)}
            disabled={isRunning}
            className="flex-1 min-w-[200px] flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-army-500 to-army-600 text-white font-semibold rounded-lg hover:from-army-600 hover:to-army-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm hover:shadow-md"
          >
            {isRunning ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent" />
                Running Pipeline...
              </>
            ) : (
              <>
                <PlayIcon className="w-5 h-5" />
                Start Real Pipeline
              </>
            )}
          </button>

          <button
            onClick={() => onDemo(authToken || undefined)}
            disabled={isRunning}
            className="flex-1 min-w-[200px] flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-500 to-blue-600 text-white font-semibold rounded-lg hover:from-blue-600 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm hover:shadow-md"
          >
            <BeakerIcon className="w-5 h-5" />
            Quick Demo
          </button>

          <button
            onClick={() => setShowTokenInput(!showTokenInput)}
            className="px-6 py-3 bg-white border-2 border-gray-300 text-gray-700 font-medium rounded-lg hover:bg-gray-50 transition-colors"
          >
            {showTokenInput ? 'Hide' : 'Set'} Token
          </button>
        </div>

        {isRunning && (
          <div className="mt-6 p-4 bg-army-50 border-l-4 border-army-500 rounded-r-lg">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="w-3 h-3 bg-army-500 rounded-full animate-ping absolute" />
                <div className="w-3 h-3 bg-army-600 rounded-full" />
              </div>
              <div>
                <p className="text-sm font-medium text-army-900">Pipeline Running</p>
                <p className="text-xs text-army-700">Check the trace panel below for real-time updates</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}