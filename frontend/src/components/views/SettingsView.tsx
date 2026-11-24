import React, { useEffect, useState } from 'react';
import { Sliders, Key, ShieldCheck, Cpu, Check, AlertCircle, RefreshCw } from 'lucide-react';
import { api } from '../../services/api';

export const SettingsView: React.FC = () => {
  const [benchmarks, setBenchmarks] = useState<any>(null);
  const [loadingBench, setLoadingBench] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setLoadingBench(true);
    api.getBenchmarks()
      .then(res => setBenchmarks(res))
      .catch(console.error)
      .finally(() => setLoadingBench(false));
  }, []);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-16">
      <div>
        <div className="flex items-center space-x-2 text-xs font-mono uppercase text-cobalt-400 mb-1">
          <Sliders className="w-3.5 h-3.5" />
          <span>System &amp; API Controls</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100">Settings &amp; Threat Intelligence API Configuration</h1>
        <p className="text-xs text-slate-400 mt-1">
          Configure optional commercial threat intelligence API keys. All keys remain server-side and are never exposed to browser clients.
        </p>
      </div>

      {/* API Key Form */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <form onSubmit={handleSave} className="space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-300 pb-2 border-b border-slate-800">
            Threat Intelligence Credentials (Optional)
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Google Safe Browsing v4 Key
              </label>
              <input
                type="password"
                placeholder="AIzaSy..."
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono outline-none focus:border-cobalt-500"
              />
              <span className="text-[10px] text-slate-400 mt-1 block">Enables real-time Google threat repository queries</span>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                VirusTotal v3 API Key
              </label>
              <input
                type="password"
                placeholder="e.g. 64-character VT key"
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono outline-none focus:border-cobalt-500"
              />
              <span className="text-[10px] text-slate-400 mt-1 block">Multi-engine antivirus telemetry (70+ vendors)</span>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                AbuseIPDB v2 Key
              </label>
              <input
                type="password"
                placeholder="AbuseIPDB key..."
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono outline-none focus:border-cobalt-500"
              />
              <span className="text-[10px] text-slate-400 mt-1 block">IP abuse confidence score and blacklist telemetry</span>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                urlscan.io API Key
              </label>
              <input
                type="password"
                placeholder="urlscan key..."
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono outline-none focus:border-cobalt-500"
              />
              <span className="text-[10px] text-slate-400 mt-1 block">Passive DOM and web screenshot search</span>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
            <span className="text-[11px] font-mono text-slate-400">
              Note: Free open feeds (URLhaus, RDAP, Cloudflare DoH, crt.sh) are active by default with zero configuration required.
            </span>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cobalt-600 hover:bg-cobalt-500 text-white text-xs font-semibold transition-all flex items-center space-x-1"
            >
              {saved && <Check className="w-3.5 h-3.5" />}
              <span>{saved ? 'Saved' : 'Save Configurations'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Benchmarks & Empirical Evaluation Metrics */}
      {benchmarks && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 block">
                Section 16 · Ground-Truth Benchmarking &amp; Validation Suite
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                Evaluation Corpus: {benchmarks.dataset_name} ({benchmarks.sample_size} Curated Cases)
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">Precision</span>
              <span className="text-2xl font-extrabold font-mono text-emerald-400 mt-1 block">
                {benchmarks.metrics.precision}%
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">Recall</span>
              <span className="text-2xl font-extrabold font-mono text-emerald-400 mt-1 block">
                {benchmarks.metrics.recall}%
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">F1 Score</span>
              <span className="text-2xl font-extrabold font-mono text-cobalt-400 mt-1 block">
                {benchmarks.metrics.f1_score}%
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">Avg Latency</span>
              <span className="text-2xl font-extrabold font-mono text-cyan-400 mt-1 block">
                {benchmarks.metrics.average_latency_ms}ms
              </span>
            </div>
          </div>

          <div className="mt-4 p-3 rounded-lg bg-slate-950/40 border border-slate-800 text-[11px] text-slate-400 leading-relaxed font-mono">
            {benchmarks.limitations[0]}
          </div>
        </div>
      )}
    </div>
  );
};
