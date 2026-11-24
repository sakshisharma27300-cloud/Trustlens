import React, { useState } from 'react';
import { Sparkles, Sliders, ArrowRight, RefreshCw, AlertCircle, Check } from 'lucide-react';
import { api } from '../../services/api';
import { CounterfactualVerdictResult, VerdictCategory } from '../../types';

interface CounterfactualProps {
  investigationId: string;
  originalRiskScore: number;
  originalVerdict: VerdictCategory;
}

export const CounterfactualSimulator: React.FC<CounterfactualProps> = ({
  investigationId,
  originalRiskScore,
  originalVerdict,
}) => {
  const [params, setParams] = useState({
    domain_age_years: 0,
    recruiter_domain_matched: false,
    remove_payment_demand: false,
    simulate_reputation_hit: false,
    has_ev_cert: false,
  });

  const [loading, setLoading] = useState(false);
  const [simResult, setSimResult] = useState<CounterfactualVerdictResult | null>(null);

  const runSimulation = async () => {
    try {
      setLoading(true);
      const res = await api.simulateCounterfactual(investigationId, params);
      setSimResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getVerdictBadge = (v: VerdictCategory) => {
    switch (v) {
      case 'Confirmed Malicious':
        return 'bg-red-500/20 text-red-300 border-red-500/40';
      case 'High Risk / Likely Malicious':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'Suspicious':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'Low Risk':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
      default:
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    }
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
        <Sparkles className="w-4 h-4 text-amber-400" />
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
          What Would Change the Verdict? (Counterfactual Simulation Engine)
        </h3>
      </div>
      <p className="text-xs text-slate-400 mt-2">
        Explore what-if counterfactual scenarios to understand which security factors drove the verdict.
        Simulated modifications are calculated independently and do not alter historical records.
      </p>

      {/* Toggles and Knobs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 my-4">
        {/* Toggle 1 */}
        <label className="flex items-start space-x-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition-colors">
          <input
            type="checkbox"
            checked={params.domain_age_years >= 3}
            onChange={(e) => setParams({ ...params, domain_age_years: e.target.checked ? 3 : 0 })}
            className="mt-1 rounded bg-slate-900 border-slate-700 text-cobalt-600 focus:ring-cobalt-500"
          />
          <div>
            <span className="text-xs font-medium text-slate-200 block">Established Domain (&gt;3 Years)</span>
            <span className="text-[11px] text-slate-400">Eliminates brand-new registration age penalty (-35 pts)</span>
          </div>
        </label>

        {/* Toggle 2 */}
        <label className="flex items-start space-x-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition-colors">
          <input
            type="checkbox"
            checked={params.recruiter_domain_matched}
            onChange={(e) => setParams({ ...params, recruiter_domain_matched: e.target.checked })}
            className="mt-1 rounded bg-slate-900 border-slate-700 text-cobalt-600 focus:ring-cobalt-500"
          />
          <div>
            <span className="text-xs font-medium text-slate-200 block">Enterprise Domain Email Alignment</span>
            <span className="text-[11px] text-slate-400">Recruiter uses @corporate.com rather than free webmail (-40 pts)</span>
          </div>
        </label>

        {/* Toggle 3 */}
        <label className="flex items-start space-x-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition-colors">
          <input
            type="checkbox"
            checked={params.remove_payment_demand}
            onChange={(e) => setParams({ ...params, remove_payment_demand: e.target.checked })}
            className="mt-1 rounded bg-slate-900 border-slate-700 text-cobalt-600 focus:ring-cobalt-500"
          />
          <div>
            <span className="text-xs font-medium text-slate-200 block">Remove Upfront Fee Demand</span>
            <span className="text-[11px] text-slate-400">Eliminates advance-fee scam indicator (-50 pts)</span>
          </div>
        </label>

        {/* Toggle 4 */}
        <label className="flex items-start space-x-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition-colors">
          <input
            type="checkbox"
            checked={params.has_ev_cert}
            onChange={(e) => setParams({ ...params, has_ev_cert: e.target.checked })}
            className="mt-1 rounded bg-slate-900 border-slate-700 text-cobalt-600 focus:ring-cobalt-500"
          />
          <div>
            <span className="text-xs font-medium text-slate-200 block">Validated EV/OV Certificate</span>
            <span className="text-[11px] text-slate-400">Verified corporate legal identity in certificate (-15 pts)</span>
          </div>
        </label>

        {/* Toggle 5 */}
        <label className="flex items-start space-x-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition-colors">
          <input
            type="checkbox"
            checked={params.simulate_reputation_hit}
            onChange={(e) => setParams({ ...params, simulate_reputation_hit: e.target.checked })}
            className="mt-1 rounded bg-slate-900 border-slate-700 text-cobalt-600 focus:ring-cobalt-500"
          />
          <div>
            <span className="text-xs font-medium text-slate-200 block">Simulate Threat Feed Match</span>
            <span className="text-[11px] text-slate-400">Entity listed on live malware/phishing repository (+60 pts)</span>
          </div>
        </label>
      </div>

      <div className="flex items-center space-x-3">
        <button
          onClick={runSimulation}
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cobalt-600 hover:bg-cobalt-500 text-white text-xs font-semibold transition-all disabled:opacity-50"
        >
          {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sliders className="w-3.5 h-3.5" />}
          <span>Recompute Simulated Verdict</span>
        </button>
      </div>

      {/* Simulation Outcome Comparison */}
      {simResult && (
        <div className="mt-4 p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pb-3 border-b border-slate-800">
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-400">Original Investigation</span>
              <div className="flex items-center space-x-2 mt-1">
                <span className={`text-xs px-2 py-0.5 rounded border ${getVerdictBadge(simResult.original_verdict)}`}>
                  {simResult.original_verdict}
                </span>
                <span className="text-xs font-mono text-slate-400">({simResult.original_risk_score} pts)</span>
              </div>
            </div>
            <div>
              <span className="text-[10px] font-mono uppercase text-amber-400 flex items-center space-x-1">
                <Sparkles className="w-3 h-3" />
                <span>Simulated Counterfactual Outcome</span>
              </span>
              <div className="flex items-center space-x-2 mt-1">
                <span className={`text-xs px-2 py-0.5 rounded border ${getVerdictBadge(simResult.simulated_verdict)}`}>
                  {simResult.simulated_verdict}
                </span>
                <span className="text-xs font-mono font-bold text-slate-200">({simResult.simulated_risk_score} pts)</span>
              </div>
            </div>
          </div>

          <p className="text-xs text-slate-300 font-mono">{simResult.delta_explanation}</p>

          {simResult.divergent_factors.length > 0 && (
            <div>
              <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1">Divergence Factors:</span>
              <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                {simResult.divergent_factors.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
