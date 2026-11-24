import React, { useState } from 'react';
import { Globe, Shield, ArrowRight, RefreshCw, AlertCircle, CheckCircle2, Lock, Cpu } from 'lucide-react';
import { api } from '../../services/api';
import { InvestigationReport } from '../../types';

interface WebsiteInvestigatorProps {
  onInvestigationComplete: (report: InvestigationReport) => void;
}

export const WebsiteInvestigatorView: React.FC<WebsiteInvestigatorProps> = ({ onInvestigationComplete }) => {
  const [url, setUrl] = useState('');
  const [deepInspection, setDeepInspection] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const report = await api.investigateWebsite(url, deepInspection);
      onInvestigationComplete(report);
    } catch (err: any) {
      setError(err.message || 'Failed to complete website investigation');
    } finally {
      setLoading(false);
    }
  };

  const sampleTargets = [
    { label: 'Unfamiliar Shopping Portal', url: 'https://super-deals-electronics-clearance.xyz' },
    { label: 'Fake Bank Verification', url: 'http://chase-bank-verify-account.top/login.php' },
    { label: 'Cloud Login Impersonation', url: 'https://login-microsoftonline-verify.servehttp.com' },
    { label: 'Crypto AirDrop Claim', url: 'https://free-crypto-token-reward-claim99.click' }
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      <div>
        <div className="flex items-center space-x-2 text-xs font-mono uppercase text-cobalt-400 mb-1">
          <Globe className="w-3.5 h-3.5" />
          <span>Flagship Workspace A · Global Website Investigator</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100">Investigate Any Website Globally</h1>
        <p className="text-xs text-slate-400 mt-1">
          Performs an 8-stage investigation pipeline: URL structure, DoH DNS records, RDAP/WHOIS registry,
          TLS certificates, SSRF-protected safe HTML inspection, brand typo-squatting, and multi-engine threat feeds.
        </p>
      </div>

      {/* Input Form Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1.5">
              Target Website URL or Domain Name
            </label>
            <div className="relative">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="e.g. https://unknown-shopping-portal.xyz or suspicious-domain.com"
                className="w-full px-4 py-3 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:border-cobalt-500 focus:ring-1 focus:ring-cobalt-500 outline-none transition-all pr-24"
                disabled={loading}
              />
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="absolute right-1.5 top-1.5 bottom-1.5 px-4 rounded-md bg-cobalt-600 hover:bg-cobalt-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-all disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <span>Investigate</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 text-xs text-slate-400">
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={deepInspection}
                onChange={(e) => setDeepInspection(e.target.checked)}
                className="rounded bg-slate-900 border-slate-700 text-cobalt-600 focus:ring-cobalt-500"
              />
              <span>Enable Safe Content Inspection (SSRF-protected sandbox, form extraction)</span>
            </label>

            <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1">
              <Lock className="w-3 h-3 text-emerald-400" />
              <span>Strict SSRF Defense &amp; Isolation Active</span>
            </span>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-start space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{error}</span>
            </div>
          )}
        </form>

        {/* Sample inputs */}
        <div className="mt-6 pt-4 border-t border-slate-800">
          <span className="text-[11px] font-mono uppercase text-slate-400 block mb-2">
            Or Load Test Fixtures for Immediate Verification:
          </span>
          <div className="flex flex-wrap gap-2">
            {sampleTargets.map((item, i) => (
              <button
                key={i}
                type="button"
                onClick={() => setUrl(item.url)}
                className="px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-800 text-slate-300 text-xs font-mono border border-slate-700/80 transition-colors"
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 8-Stage Pipeline Visualization */}
      <div className="bg-slate-900/40 border border-slate-800/80 rounded-xl p-5">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 block mb-3">
          Automated 8-Stage Investigation Pipeline
        </span>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          {[
            { step: '01', title: 'URL & Domain', desc: 'Entropy, Punycode, TLD' },
            { step: '02', title: 'DNS over HTTPS', desc: 'A, AAAA, MX, NS, TXT' },
            { step: '03', title: 'RDAP Lifecycle', desc: 'Age, Registrar, Expiry' },
            { step: '04', title: 'TLS Inspection', desc: 'SANs, Issuer, Validity' },
            { step: '05', title: 'Content Isolation', desc: 'SSRF Sandbox, Forms' },
            { step: '06', title: 'Brand Impersonation', desc: 'Squatting & Typo checks' },
            { step: '07', title: 'Reputation Feeds', desc: 'URLhaus, SafeBrowsing' },
            { step: '08', title: 'Risk Fusion', desc: 'Tri-Axis & Correlation' }
          ].map((st) => (
            <div key={st.step} className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <span className="text-[10px] text-cobalt-400 font-bold block mb-1">STAGE {st.step}</span>
              <span className="text-slate-200 font-semibold block">{st.title}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">{st.desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
