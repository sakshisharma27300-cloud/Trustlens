import React, { useState, useEffect } from 'react';
import { 
  Award, Sparkles, ArrowRight, RefreshCw, CheckCircle, 
  AlertTriangle, Shield, Globe, ExternalLink, Play, Layers 
} from 'lucide-react';
import { api } from '../../services/api';
import { JudgeScenario, InvestigationReport } from '../../types';

interface LiveJudgeProps {
  onInvestigationComplete: (report: InvestigationReport) => void;
}

export const LiveJudgeChallengeView: React.FC<LiveJudgeProps> = ({ onInvestigationComplete }) => {
  const [scenarios, setScenarios] = useState<JudgeScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<JudgeScenario | null>(null);
  const [activeStage, setActiveStage] = useState<number>(0);
  const [loading, setLoading] = useState(false);
  const [customInput, setCustomInput] = useState('');
  const [customType, setCustomType] = useState('website');

  useEffect(() => {
    api.getScenarios().then(res => {
      setScenarios(res);
      if (res.length > 0) setSelectedScenario(res[0]);
    }).catch(console.error);
  }, []);

  const stages = [
    { num: 1, name: 'Input Classification', desc: 'Categorize entity schema, channel, and target type.' },
    { num: 2, name: 'Entity Extraction', desc: 'Extract hostnames, credentials, emails, and phone markers.' },
    { num: 3, name: 'Technical Intelligence', desc: 'Query DoH DNS, RDAP lifecycle, TLS certificates.' },
    { num: 4, name: 'Independent Detection', desc: 'Execute 16 analytical engines in isolated parallel pipelines.' },
    { num: 5, name: 'Reputation Feeds', desc: 'Query live URLhaus, OpenPhish, PhishTank, SafeBrowsing.' },
    { num: 6, name: 'Evidence Correlation', desc: 'Cross-reference disparate layer anomalies into attack chains.' },
    { num: 7, name: 'Risk Fusion Verdict', desc: 'Generate Tri-Axis scores and 22-section forensic report.' }
  ];

  const runChallenge = async (scenario: JudgeScenario) => {
    try {
      setLoading(true);
      setActiveStage(1);
      
      // Simulate live stage progression for interactive visual feedback
      const timer = setInterval(() => {
        setActiveStage(prev => {
          if (prev < 6) return prev + 1;
          clearInterval(timer);
          return 6;
        });
      }, 350);

      let report: InvestigationReport;
      if (scenario.type === 'website') {
        report = await api.investigateWebsite(scenario.input_data.url, true);
      } else if (scenario.type === 'email') {
        report = await api.investigateEmail(scenario.input_data);
      } else if (scenario.type === 'message') {
        report = await api.investigateMessage(scenario.input_data.content, scenario.input_data.channel);
      } else if (scenario.type === 'job_offer') {
        report = await api.investigateJobOffer(scenario.input_data as any);
      } else {
        report = await api.investigateURL(scenario.input_data.url);
      }

      clearInterval(timer);
      setActiveStage(7);
      setTimeout(() => {
        onInvestigationComplete(report);
      }, 700);

    } catch (err) {
      console.error(err);
      setActiveStage(0);
    } finally {
      setLoading(false);
    }
  };

  const handleCustomSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customInput.trim()) return;

    const pseudoScenario: JudgeScenario = {
      id: 'custom-judge-input',
      title: 'Custom Live Judge Submission',
      type: customType as any,
      description: 'Arbitrary unfamiliar digital entity submitted by judge.',
      input_data: customType === 'website' ? { url: customInput } : customType === 'message' ? { content: customInput, channel: 'general' } : { url: customInput },
      expected_verdict: 'Live Automated Assessment',
      highlights: ['Unseen live entity', 'Real-time multi-engine analysis']
    };
    runChallenge(pseudoScenario);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-16">
      {/* Header */}
      <div className="rounded-2xl bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-900 border border-amber-500/30 p-6 sm:p-8">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-mono uppercase text-amber-400 mb-1">
              <Award className="w-4 h-4" />
              <span>Section 17 · Hackathon Live Judge Challenge Mode</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100">
              Real-World Unfamiliar Threat Investigation
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl">
              TRUSTLENS GLOBAL investigates unfamiliar websites, emails, and recruitment communications submitted in real time.
              Choose from 10 realistic evaluation fixtures or submit any arbitrary website or communication.
            </p>
          </div>

          <div className="text-right font-mono text-xs">
            <span className="text-[10px] text-slate-400 uppercase block">Evaluation Mode</span>
            <span className="text-amber-400 font-bold">16 ENGINES ACTIVE</span>
          </div>
        </div>
      </div>

      {/* 7-Stage Visual Pipeline */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-amber-400" />
            <span>Progressive 7-Stage Live Execution Pipeline</span>
          </span>
          <span className="text-[11px] font-mono text-slate-400">
            {loading ? `Executing Stage ${activeStage} of 7...` : 'Ready for Challenge Input'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-7 gap-2">
          {stages.map((st) => {
            const isCompleted = activeStage > st.num;
            const isCurrent = activeStage === st.num;

            return (
              <div
                key={st.num}
                className={`p-3 rounded-lg border text-xs font-mono transition-all ${
                  isCurrent
                    ? 'bg-amber-500/20 border-amber-500/50 text-amber-200 ring-1 ring-amber-500/30'
                    : isCompleted
                    ? 'bg-slate-900/90 border-emerald-500/40 text-emerald-300'
                    : 'bg-slate-950/60 border-slate-800/80 text-slate-400'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-bold">STAGE 0{st.num}</span>
                  {isCompleted && <CheckCircle className="w-3 h-3 text-emerald-400" />}
                  {isCurrent && <RefreshCw className="w-3 h-3 text-amber-400 animate-spin" />}
                </div>
                <span className="font-semibold block text-slate-200 truncate">{st.name}</span>
                <span className="text-[10px] text-slate-400 block mt-1 leading-snug line-clamp-2">
                  {st.desc}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Custom Arbitrary Judge Submission Testbed */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <h2 className="text-sm font-bold text-slate-100 mb-1">
          Judge Live Arbitrary Input Testbed
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Submit any unfamiliar public URL or suspicious communication brought by a judge to test the platform on zero-day unseen data.
        </p>

        <form onSubmit={handleCustomSubmit} className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className="text-xs text-slate-400">Target Type:</span>
            {['website', 'message', 'url'].map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setCustomType(t)}
                className={`px-2.5 py-1 rounded text-xs font-mono uppercase ${
                  customType === t
                    ? 'bg-amber-500 text-slate-950 font-bold'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap gap-2">
            <input
              type="text"
              value={customInput}
              onChange={(e) => setCustomInput(e.target.value)}
              placeholder="e.g. Enter any unfamiliar URL or message text to execute live investigation..."
              className="flex-1 px-4 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:border-amber-500 outline-none"
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !customInput.trim()}
              className="px-5 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-slate-950 text-xs font-bold flex items-center space-x-1.5 transition-all disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              <span>Execute Live Judge Test</span>
            </button>
          </div>
        </form>
      </div>

      {/* 10 Curated Realistic Judge Scenarios Grid */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-bold text-slate-100">10 Curated Hackathon Judge Scenarios</h2>
            <p className="text-xs text-slate-400">Pre-calibrated test cases across websites, emails, recruitment, and messages</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scenarios.map((scen, idx) => (
            <div
              key={scen.id}
              className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-amber-400 uppercase font-bold">
                    Case 0{idx + 1} · {scen.type}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">
                    Expected: {scen.expected_verdict}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-slate-100">{scen.title}</h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  {scen.description}
                </p>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  {scen.highlights.map((h, i) => (
                    <span
                      key={i}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800/80"
                    >
                      {h}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-end">
                <button
                  onClick={() => runChallenge(scen)}
                  disabled={loading}
                  className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-amber-300 text-xs font-semibold flex items-center space-x-1.5 transition-colors border border-amber-500/30 disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 text-amber-400" />
                  <span>Run This Investigation</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
