import React from 'react';
import { AlertTriangle, CheckCircle, HelpCircle, ShieldAlert, Cpu, Crosshair } from 'lucide-react';
import { VerdictCategory } from '../../types';

interface TriAxisProps {
  riskScore: number;
  confidence: number;
  coverage: number;
  verdict: VerdictCategory;
}

export const TriAxisMetrics: React.FC<TriAxisProps> = ({ riskScore, confidence, coverage, verdict }) => {
  const getVerdictStyle = (v: VerdictCategory) => {
    switch (v) {
      case 'Confirmed Malicious':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'High Risk / Likely Malicious':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'Suspicious':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'Low Risk':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
      case 'No Significant Risk Detected':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-400';
    if (score >= 50) return 'text-amber-400';
    if (score >= 25) return 'text-blue-400';
    return 'text-emerald-400';
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
      {/* 1. Overall Verdict */}
      <div className="flex flex-col justify-between p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-cobalt-400" />
          <span>Overall Verdict</span>
        </span>
        <div className="my-2">
          <span className={`inline-block px-2.5 py-1 rounded-md text-xs font-semibold border ${getVerdictStyle(verdict)}`}>
            {verdict}
          </span>
        </div>
        <p className="text-[11px] text-slate-400">Synthesized multi-layer assessment</p>
      </div>

      {/* 2. Risk Score */}
      <div className="flex flex-col justify-between p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>Risk Score</span>
          </span>
          <span className="text-[10px] font-mono text-slate-400">0 - 100</span>
        </div>
        <div className="my-2 flex items-baseline space-x-1">
          <span className={`text-3xl font-extrabold font-mono ${getRiskColor(riskScore)}`}>
            {riskScore.toFixed(1)}
          </span>
          <span className="text-xs text-slate-400">/ 100</span>
        </div>
        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
          <div
            className={`h-full transition-all duration-500 ${
              riskScore >= 75 ? 'bg-red-500' : riskScore >= 45 ? 'bg-amber-500' : 'bg-emerald-500'
            }`}
            style={{ width: `${Math.min(riskScore, 100)}%` }}
          />
        </div>
      </div>

      {/* 3. Assessment Confidence */}
      <div className="flex flex-col justify-between p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
            <Crosshair className="w-3.5 h-3.5 text-cobalt-400" />
            <span>Confidence</span>
          </span>
          <span className="text-[10px] font-mono text-slate-400">%</span>
        </div>
        <div className="my-2 flex items-baseline space-x-1">
          <span className="text-3xl font-extrabold font-mono text-cobalt-400">
            {confidence.toFixed(1)}%
          </span>
        </div>
        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
          <div
            className="h-full bg-cobalt-500 transition-all duration-500"
            style={{ width: `${Math.min(confidence, 100)}%` }}
          />
        </div>
      </div>

      {/* 4. Analysis Coverage */}
      <div className="flex flex-col justify-between p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Coverage</span>
          </span>
          <span className="text-[10px] font-mono text-slate-400">16 Engines</span>
        </div>
        <div className="my-2 flex items-baseline space-x-1">
          <span className="text-3xl font-extrabold font-mono text-cyan-400">
            {coverage.toFixed(1)}%
          </span>
        </div>
        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
          <div
            className="h-full bg-cyan-500 transition-all duration-500"
            style={{ width: `${Math.min(coverage, 100)}%` }}
          />
        </div>
      </div>
    </div>
  );
};
