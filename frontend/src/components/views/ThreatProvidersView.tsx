import React, { useEffect, useState } from 'react';
import { Activity, Shield, ExternalLink, RefreshCw, CheckCircle, AlertTriangle, Key } from 'lucide-react';
import { api } from '../../services/api';
import { ProviderInfo } from '../../types';

export const ThreatProvidersView: React.FC = () => {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchProviders = () => {
    setLoading(true);
    api.getProviders()
      .then(res => setProviders(res))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchProviders();
  }, []);

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono uppercase text-cobalt-400 mb-1">
            <Activity className="w-3.5 h-3.5" />
            <span>Telemetry &amp; Feeds</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100">Global Threat Intelligence Connectors</h1>
          <p className="text-xs text-slate-400 mt-1">
            Monitors real-time connectivity, latency, and query status across open and authenticated threat repositories.
          </p>
        </div>

        <button
          onClick={fetchProviders}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Feed Status</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {providers.map((p, idx) => {
          const isOperational = p.status.includes('Operational');
          const isAwaitingKey = p.status.includes('Awaiting');

          return (
            <div
              key={idx}
              className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {p.type}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                      isOperational
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : isAwaitingKey
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-slate-500/20 text-slate-300 border border-slate-500/40'
                    }`}
                  >
                    {isOperational ? 'LIVE' : isAwaitingKey ? 'OPTIONAL KEY' : 'OFFLINE'}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-slate-100">{p.name}</h3>
                <span className="text-[11px] font-mono text-cobalt-400 block mt-0.5">{p.category}</span>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Status: {p.status}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Latency: {p.latency}</span>
                <a
                  href={p.attribution}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center space-x-1 text-cobalt-400 hover:text-cobalt-300"
                >
                  <span>Docs</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
