import React, { useState } from 'react';
import { Search, Globe, AlertCircle, Zap, Eye } from 'lucide-react';
import { ScanMode } from '../types';

interface ScannerInputProps {
  onScan: (url: string, mode: ScanMode) => void;
  isLoading: boolean;
}

const ScannerInput: React.FC<ScannerInputProps> = ({ onScan, isLoading }) => {
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState<ScanMode>(ScanMode.PASSIVE);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Target undefined. Enter a valid domain.');
      return;
    }
    setError('');
    onScan(url, mode);
  };

  return (
    <div className="w-full max-w-3xl mx-auto mb-12">
      <div className="bg-slate-900/80 p-6 rounded-xl border border-slate-700 shadow-2xl backdrop-blur-md relative overflow-hidden">
        {/* Decorative elements */}
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-500 via-purple-500 to-red-500 opacity-50"></div>
        
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex items-center gap-4 mb-2">
                <button
                    type="button"
                    onClick={() => setMode(ScanMode.PASSIVE)}
                    className={`flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-lg border transition-all ${mode === ScanMode.PASSIVE ? 'bg-cyan-900/30 border-cyan-500 text-cyan-400' : 'bg-slate-800 border-slate-700 text-slate-500 hover:border-slate-600'}`}
                >
                    <Eye className="w-4 h-4" />
                    <span className="font-mono text-sm">PASSIVE_SCAN</span>
                </button>
                <button
                    type="button"
                    onClick={() => setMode(ScanMode.AGGRESSIVE)}
                    className={`flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-lg border transition-all ${mode === ScanMode.AGGRESSIVE ? 'bg-red-900/30 border-red-500 text-red-400' : 'bg-slate-800 border-slate-700 text-slate-500 hover:border-slate-600'}`}
                >
                    <Zap className="w-4 h-4" />
                    <span className="font-mono text-sm">AGGRESSIVE_MODE</span>
                </button>
            </div>

          <div className="relative flex items-center group">
            <div className="absolute left-4 text-slate-500 group-focus-within:text-cyan-400 transition-colors">
              <Globe className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="TARGET_DOMAIN (e.g., example.com)"
              className="w-full bg-slate-950 text-white pl-12 pr-40 py-4 rounded-lg focus:outline-none focus:ring-1 focus:ring-cyan-500/50 border border-slate-700 focus:border-cyan-500/50 transition-all font-mono placeholder-slate-600 text-lg tracking-wide"
              disabled={isLoading}
            />
            <button
              type="submit"
              disabled={isLoading}
              className={`absolute right-2 px-6 py-2 rounded-md font-bold text-sm tracking-wider transition-all duration-200 uppercase
                ${isLoading 
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700' 
                  : mode === ScanMode.AGGRESSIVE 
                    ? 'bg-red-600 hover:bg-red-500 text-white shadow-[0_0_15px_rgba(220,38,38,0.5)] border border-red-400'
                    : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-[0_0_15px_rgba(8,145,178,0.5)] border border-cyan-400'
                }`}
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-white rounded-full animate-bounce" />
                  EXECUTING
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Search className="w-4 h-4" />
                  {mode === ScanMode.AGGRESSIVE ? 'ATTACK' : 'SCAN'}
                </span>
              )}
            </button>
          </div>
        </form>
      </div>
      {error && (
        <div className="mt-3 flex items-center gap-2 text-red-400 text-sm animate-pulse px-4 font-mono bg-red-900/10 p-2 rounded border border-red-900/30">
          <AlertCircle className="w-4 h-4" />
          ERROR: {error}
        </div>
      )}
    </div>
  );
};

export default ScannerInput;
