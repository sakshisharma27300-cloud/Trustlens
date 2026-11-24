import React from 'react';
import { Shield, Activity, Globe, Award, Sparkles } from 'lucide-react';

interface HeaderProps {
  currentView: string;
  onNavigate: (view: string) => void;
  onLaunchJudgeChallenge: () => void;
}

export const Header: React.FC<HeaderProps> = ({ currentView, onNavigate, onLaunchJudgeChallenge }) => {
  return (
    <header className="sticky top-0 z-50 bg-slate-950/80 backdrop-blur-md border-b border-slate-800 px-6 py-3.5 flex items-center justify-between">
      <div className="flex items-center space-x-3 cursor-pointer" onClick={() => onNavigate('dashboard')}>
        <div className="w-9 h-9 rounded-lg bg-cobalt-600/20 border border-cobalt-500/40 flex items-center justify-center text-cobalt-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold tracking-tight text-slate-100 text-lg">TRUSTLENS</span>
            <span className="text-[10px] font-mono tracking-wider uppercase px-1.5 py-0.5 rounded bg-cobalt-950 text-cobalt-400 border border-cobalt-800">
              GLOBAL
            </span>
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block">Digital Threat & Scam Intelligence Platform</p>
        </div>
      </div>

      <nav className="hidden lg:flex items-center space-x-1 text-sm font-medium">
        {[
          { id: 'dashboard', label: 'Dashboard' },
          { id: 'website', label: 'Website Investigator' },
          { id: 'url', label: 'URL Threat' },
          { id: 'email', label: 'Email Forensics' },
          { id: 'message', label: 'Message Analyzer' },
          { id: 'job_offer', label: 'Job Verifier' },
          { id: 'providers', label: 'Intelligence Feeds' },
          { id: 'history', label: 'History' },
          { id: 'learning', label: 'Learning Center' },
          { id: 'settings', label: 'Settings' },
        ].map(item => (
          <button
            key={item.id}
            onClick={() => onNavigate(item.id)}
            className={`px-3 py-1.5 rounded-md text-xs transition-colors ${
              currentView === item.id
                ? 'bg-cobalt-600/20 text-cobalt-300 border border-cobalt-500/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <div className="flex items-center space-x-2">
        <button
          onClick={onLaunchJudgeChallenge}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-gradient-to-r from-amber-500/20 to-orange-500/20 border border-amber-500/40 text-amber-300 hover:bg-amber-500/30 text-xs font-semibold shadow-sm transition-all"
        >
          <Award className="w-3.5 h-3.5 text-amber-400" />
          <span>Live Judge Challenge</span>
        </button>
      </div>
    </header>
  );
};
