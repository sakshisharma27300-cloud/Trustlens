import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, Globe, Link, Mail, MessageSquare, Briefcase, 
  ArrowRight, Activity, Cpu, CheckCircle2, AlertTriangle, 
  ExternalLink, Sparkles, BookOpen 
} from 'lucide-react';
import { api } from '../../services/api';
import { DashboardSummary } from '../../types';

interface DashboardProps {
  onNavigate: (view: string) => void;
  onSelectInvestigation: (report: any) => void;
  onLaunchJudgeChallenge: () => void;
}

export const DashboardView: React.FC<DashboardProps> = ({ 
  onNavigate, onSelectInvestigation, onLaunchJudgeChallenge 
}) => {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getDashboard()
      .then(res => setData(res))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const workspaces = [
    {
      id: 'website',
      title: 'Global Website Investigator',
      desc: 'Flagship 8-stage pipeline analyzing unknown websites, DNS, RDAP, TLS, SSRF-safe content, and brand impersonation.',
      icon: Globe,
      color: 'text-cobalt-400',
      tag: 'Flagship'
    },
    {
      id: 'url',
      title: 'URL Threat Intelligence',
      desc: 'Structural URL scanner detecting obfuscation, Punycode homoglyphs, deep subdomains, and malicious feeds.',
      icon: Link,
      color: 'text-cyan-400',
      tag: 'Scanner'
    },
    {
      id: 'email',
      title: 'Email Forensics Engine',
      desc: 'RFC 822 email parser for SPF, DKIM, DMARC alignment, display name spoofing, and Reply-To divergence.',
      icon: Mail,
      color: 'text-indigo-400',
      tag: 'Forensics'
    },
    {
      id: 'message',
      title: 'Message & Social Engineering',
      desc: 'Multilingual detector for WhatsApp, SMS, Telegram, Digital Arrest, Courier scams, and coercive extortion.',
      icon: MessageSquare,
      color: 'text-emerald-400',
      tag: 'Multilingual'
    },
    {
      id: 'job_offer',
      title: 'Job & Organization Authenticity',
      desc: 'Recruitment verification distinguishing company existence from genuine offers and upfront payment demands.',
      icon: Briefcase,
      color: 'text-amber-400',
      tag: 'Verification'
    }
  ];

  return (
    <div className="max-w-7xl mx-auto space-y-8 pb-12">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800 p-8 sm:p-10">
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cobalt-950/80 border border-cobalt-800/80 text-cobalt-400 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-cobalt-400 animate-pulse"></span>
            <span>TRUSTLENS GLOBAL CORE 2.4 ONLINE</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-100">
            One Platform. Global Threat Intelligence. Informed Decisions.
          </h1>
          <p className="text-sm sm:text-base text-slate-400 leading-relaxed">
            Investigate suspicious websites, URLs, emails, messages, and recruitment solicitations from anywhere in the world.
            Powered by 16 independent analytical engines, live threat feeds, and evidence correlation.
          </p>
          <div className="pt-2 flex flex-wrap gap-3">
            <button
              onClick={() => onNavigate('website')}
              className="px-5 py-2.5 rounded-lg bg-cobalt-600 hover:bg-cobalt-500 text-white text-xs font-semibold shadow-md transition-all flex items-center space-x-2"
            >
              <Globe className="w-4 h-4" />
              <span>Launch Website Investigator</span>
            </button>
            <button
              onClick={onLaunchJudgeChallenge}
              className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-amber-500/20 to-orange-500/20 border border-amber-500/40 text-amber-300 hover:bg-amber-500/30 text-xs font-semibold transition-all flex items-center space-x-2"
            >
              <Sparkles className="w-4 h-4 text-amber-400" />
              <span>Hackathon Live Judge Challenge</span>
            </button>
          </div>
        </div>
      </div>

      {/* Telemetry Statistics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] font-mono uppercase text-slate-400">Total Investigations</span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-slate-100">
            {data?.total_investigations ?? 0}
          </div>
          <span className="text-[11px] text-slate-400 mt-1 block">Executed across workspaces</span>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] font-mono uppercase text-rose-400">High / Malicious Threats</span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-rose-400">
            {data?.threat_breakdown.critical_or_high_risk ?? 0}
          </div>
          <span className="text-[11px] text-slate-400 mt-1 block">Corroborated malicious entities</span>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] font-mono uppercase text-amber-400">Suspicious Entities</span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-amber-400">
            {data?.threat_breakdown.suspicious ?? 0}
          </div>
          <span className="text-[11px] text-slate-400 mt-1 block">Under forensic review</span>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] font-mono uppercase text-cyan-400">Autonomous Engines</span>
          <div className="mt-2 text-3xl font-extrabold font-mono text-cyan-400">
            {data?.active_engines ?? 16}
          </div>
          <span className="text-[11px] text-slate-400 mt-1 block">Parallel detection pipelines</span>
        </div>
      </div>

      {/* 5 Dedicated Investigation Workspaces */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-slate-100">Investigation Workspaces</h2>
            <p className="text-xs text-slate-400">Select a specialized forensic workspace to begin analysis</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {workspaces.map((ws) => {
            const Icon = ws.icon;
            return (
              <div
                key={ws.id}
                onClick={() => onNavigate(ws.id)}
                className="group p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cobalt-500/50 hover:bg-slate-900/90 cursor-pointer transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-9 h-9 rounded-lg bg-slate-800/80 border border-slate-700/80 flex items-center justify-center">
                      <Icon className={`w-5 h-5 ${ws.color}`} />
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {ws.tag}
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-100 group-hover:text-cobalt-300 transition-colors">
                    {ws.title}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                    {ws.desc}
                  </p>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center text-xs font-semibold text-cobalt-400 group-hover:translate-x-0.5 transition-transform">
                  <span>Enter Workspace</span>
                  <ArrowRight className="w-3.5 h-3.5 ml-1" />
                </div>
              </div>
            );
          })}

          {/* Quick Learning Card */}
          <div
            onClick={() => onNavigate('learning')}
            className="p-5 rounded-xl bg-gradient-to-br from-slate-900/80 to-slate-950 border border-slate-800 hover:border-slate-700 cursor-pointer flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="w-9 h-9 rounded-lg bg-slate-800/80 border border-slate-700/80 flex items-center justify-center">
                  <BookOpen className="w-5 h-5 text-purple-400" />
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                  Advisory
                </span>
              </div>
              <h3 className="text-sm font-bold text-slate-100">Security Learning Center</h3>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                Review scam taxonomies, warning indicators, and global cybercrime reporting hotlines (IC3, Europol, Cybercrime.gov.in).
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center text-xs font-semibold text-purple-400">
              <span>View Security Guides</span>
              <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </div>
          </div>
        </div>
      </div>

      {/* Recent Investigations Stream */}
      {data?.recent_investigations && data.recent_investigations.length > 0 && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
              Recent Forensic Investigations
            </span>
            <button
              onClick={() => onNavigate('history')}
              className="text-xs text-cobalt-400 hover:text-cobalt-300 transition-colors"
            >
              View Full History →
            </button>
          </div>

          <div className="divide-y divide-slate-800/80">
            {data.recent_investigations.map((rec: any) => (
              <div
                key={rec.id}
                onClick={() => onSelectInvestigation(rec.report)}
                className="py-3 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-800/30 px-2 rounded-lg cursor-pointer transition-colors"
              >
                <div className="flex items-center space-x-3">
                  <span className="text-[11px] font-mono text-slate-400 uppercase w-16">
                    {rec.type}
                  </span>
                  <div>
                    <span className="text-xs font-mono font-medium text-slate-200 hover:text-cobalt-300">
                      {rec.entity}
                    </span>
                    <p className="text-[11px] text-slate-400 truncate max-w-lg mt-0.5">
                      {rec.summary}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <span className="text-xs font-mono text-slate-300">
                    Risk: <strong className={rec.risk_score > 60 ? 'text-red-400' : 'text-emerald-400'}>{rec.risk_score}</strong>
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    {new Date(rec.created_at).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
