import React, { useState } from 'react';
import { Header } from './components/common/Header';
import { DashboardView } from './components/views/DashboardView';
import { WebsiteInvestigatorView } from './components/views/WebsiteInvestigatorView';
import { URLThreatView } from './components/views/URLThreatView';
import { EmailForensicsView } from './components/views/EmailForensicsView';
import { MessageAnalyzerView } from './components/views/MessageAnalyzerView';
import { JobVerifierView } from './components/views/JobVerifierView';
import { InvestigationReportView } from './components/common/InvestigationReportView';
import { LiveJudgeChallengeView } from './components/views/LiveJudgeChallengeView';
import { ThreatProvidersView } from './components/views/ThreatProvidersView';
import { HistoryView } from './components/views/HistoryView';
import { LearningCenterView } from './components/views/LearningCenterView';
import { SettingsView } from './components/views/SettingsView';
import { InvestigationReport } from './types';

export function App() {
  const [currentView, setCurrentView] = useState<string>('dashboard');
  const [activeReport, setActiveReport] = useState<InvestigationReport | null>(null);

  const handleInvestigationComplete = (report: InvestigationReport) => {
    setActiveReport(report);
    setCurrentView('report');
  };

  const handleSelectReport = (report: InvestigationReport) => {
    setActiveReport(report);
    setCurrentView('report');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Header
        currentView={currentView}
        onNavigate={(view) => setCurrentView(view)}
        onLaunchJudgeChallenge={() => setCurrentView('judge_challenge')}
      />

      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-6">
        {currentView === 'dashboard' && (
          <DashboardView
            onNavigate={(view) => setCurrentView(view)}
            onSelectInvestigation={handleSelectReport}
            onLaunchJudgeChallenge={() => setCurrentView('judge_challenge')}
          />
        )}

        {currentView === 'website' && (
          <WebsiteInvestigatorView
            onInvestigationComplete={handleInvestigationComplete}
          />
        )}

        {currentView === 'url' && (
          <URLThreatView
            onInvestigationComplete={handleInvestigationComplete}
          />
        )}

        {currentView === 'email' && (
          <EmailForensicsView
            onInvestigationComplete={handleInvestigationComplete}
          />
        )}

        {currentView === 'message' && (
          <MessageAnalyzerView
            onInvestigationComplete={handleInvestigationComplete}
          />
        )}

        {currentView === 'job_offer' && (
          <JobVerifierView
            onInvestigationComplete={handleInvestigationComplete}
          />
        )}

        {currentView === 'judge_challenge' && (
          <LiveJudgeChallengeView
            onInvestigationComplete={handleInvestigationComplete}
          />
        )}

        {currentView === 'providers' && (
          <ThreatProvidersView />
        )}

        {currentView === 'history' && (
          <HistoryView onSelectReport={handleSelectReport} />
        )}

        {currentView === 'learning' && (
          <LearningCenterView />
        )}

        {currentView === 'settings' && (
          <SettingsView />
        )}

        {currentView === 'report' && activeReport && (
          <InvestigationReportView
            report={activeReport}
            onBack={() => setCurrentView('dashboard')}
          />
        )}
      </main>

      <footer className="border-t border-slate-900 bg-slate-950/80 px-6 py-4 text-center text-xs text-slate-400 font-mono no-print">
        TRUSTLENS GLOBAL · Global Digital Threat Intelligence &amp; Digital Trust Platform · Version 2.4-enterprise
      </footer>
    </div>
  );
}

export default App;
