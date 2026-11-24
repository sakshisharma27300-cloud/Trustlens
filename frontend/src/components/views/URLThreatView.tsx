import React, { useState } from 'react';
import { Link, Shield, ArrowRight, RefreshCw, AlertCircle, EyeOff } from 'lucide-react';
import { api } from '../../services/api';
import { InvestigationReport } from '../../types';

interface URLThreatProps {
  onInvestigationComplete: (report: InvestigationReport) => void;
}

export const URLThreatView: React.FC<URLThreatProps> = ({ onInvestigationComplete }) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const report = await api.investigateURL(url);
      onInvestigationComplete(report);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze URL');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      <div>
        <div className="flex items-center space-x-2 text-xs font-mono uppercase text-cyan-400 mb-1">
          <Link className="w-3.5 h-3.5" />
          <span>Workspace C · Global URL Threat Intelligence</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100">Direct URL Threat Scanner</h1>
        <p className="text-xs text-slate-400 mt-1">
          Analyze bare links, shortened links (bit.ly, t.co), deep subdomain chains,
          embedded credentials ('@' separators), and homoglyph disguises without ever navigating your browser to them.
        </p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1.5">
              Submit Any Suspicious or Unfamiliar Link
            </label>
            <div className="relative">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="e.g. http://192.168.1.1@google.com-account.update.xyz/login or bit.ly/3xFake"
                className="w-full px-4 py-3 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all pr-24"
                disabled={loading}
              />
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="absolute right-1.5 top-1.5 bottom-1.5 px-4 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-all disabled:opacity-50"
              >
                {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <span>Scan URL</span>}
              </button>
            </div>
          </div>

          <div className="flex items-center space-x-2 text-[11px] text-slate-400 font-mono">
            <EyeOff className="w-3.5 h-3.5 text-cyan-400" />
            <span>Zero-Execution Policy: TRUSTLENS never navigates client browsers to submitted destinations.</span>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-start space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{error}</span>
            </div>
          )}
        </form>

        <div className="mt-6 pt-4 border-t border-slate-800">
          <span className="text-[11px] font-mono uppercase text-slate-400 block mb-2">Test Scenarios:</span>
          <div className="flex flex-wrap gap-2">
            {[
              'http://google.com@attacker-portal.net/login',
              'https://paypal.com.verification.phishkit.sbs/webscr',
              'https://bit.ly/3xFakeAirdropTokenWin',
              'http://xn--apple-43a.com/icloud'
            ].map((u, i) => (
              <button
                key={i}
                type="button"
                onClick={() => setUrl(u)}
                className="px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-800 text-slate-300 text-xs font-mono border border-slate-700/80 transition-colors"
              >
                {u}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
