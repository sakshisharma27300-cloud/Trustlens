import React, { useState } from 'react';
import { 
  Printer, ArrowLeft, Shield, AlertTriangle, CheckCircle, 
  HelpCircle, Globe, Server, Key, Mail, Cpu, Sparkles, 
  ChevronDown, ChevronUp, Network, Clock, ExternalLink 
} from 'lucide-react';
import { InvestigationReport, SeverityLevel } from '../../types';
import { TriAxisMetrics } from './TriAxisMetrics';
import { EvidenceGraphView } from './EvidenceGraphView';
import { CounterfactualSimulator } from './CounterfactualSimulator';

interface ReportViewProps {
  report: InvestigationReport;
  onBack: () => void;
}

export const InvestigationReportView: React.FC<ReportViewProps> = ({ report, onBack }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'graph' | 'engines' | 'technical' | 'counterfactual'>('overview');
  const [expandedEngine, setExpandedEngine] = useState<string | null>(null);

  const printReport = () => {
    window.print();
  };

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'critical':
        return 'bg-red-500/20 text-red-300 border-red-500/40';
      case 'high':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'medium':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'low':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6 pb-16">
      {/* Top Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 no-print">
        <button
          onClick={onBack}
          className="flex items-center space-x-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Investigation Workspace</span>
        </button>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={printReport}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Export Forensic PDF</span>
          </button>
        </div>
      </div>

      {/* Report Header (Sections 1, 2, 3, 21, 22) */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 mb-1.5">
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cobalt-950 text-cobalt-400 border border-cobalt-800">
                {report.investigation_id}
              </span>
              <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Type: {report.investigation_type}
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                Core: {report.algorithm_version}
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-100 break-all font-mono">
              {report.submitted_entity}
            </h1>
            <p className="text-xs text-slate-400 mt-1 flex items-center space-x-2">
              <Clock className="w-3 h-3" />
              <span>Timestamp: {new Date(report.investigation_timestamp).toUTCString()}</span>
            </p>
          </div>
        </div>

        {/* Sections 4, 5, 6, 7: Tri-Axis Metrics */}
        <div className="mt-6">
          <TriAxisMetrics
            riskScore={report.risk_score}
            confidence={report.assessment_confidence}
            coverage={report.analysis_coverage}
            verdict={report.overall_verdict}
          />
        </div>

        {/* Section 8: Executive Summary */}
        <div className="mt-5 p-4 rounded-lg bg-slate-950/80 border border-slate-800/80">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">
            Section 8 · Executive Summary
          </span>
          <p className="text-sm text-slate-200 leading-relaxed font-sans font-medium">
            {report.executive_summary}
          </p>
        </div>
      </div>

      {/* Workspace Navigation Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800 pb-2 no-print">
        {[
          { id: 'overview', label: 'Executive Intelligence & Evidence' },
          { id: 'graph', label: 'Correlation Graph' },
          { id: 'engines', label: `16 Detection Engines (${report.detection_engine_results.length})` },
          { id: 'technical', label: 'Technical Infrastructure' },
          { id: 'counterfactual', label: 'Counterfactual Simulation' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-3.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-cobalt-600/20 text-cobalt-300 border border-cobalt-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* TAB 1: OVERVIEW & EVIDENCE */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Section 16: Correlated Attack Narrative */}
          {report.correlated_findings.length > 0 && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 block mb-2">
                Section 16 · TRUSTLENS Cross-Layer Threat Correlation Narratives
              </span>
              <div className="space-y-2">
                {report.correlated_findings.map((narrative, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs font-mono leading-relaxed"
                  >
                    {narrative}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section 15: Forensic Evidence Excerpts */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Section 15 · Discovered Forensic Evidence ({report.evidence_excerpts.length})
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                Ranked by Multi-Layer Severity & Source Confidence
              </span>
            </div>

            {report.evidence_excerpts.length > 0 ? (
              <div className="space-y-3">
                {report.evidence_excerpts.map((ev) => (
                  <div
                    key={ev.id}
                    className="p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center space-x-2">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase border ${getSeverityBadge(ev.severity)}`}>
                          {ev.severity}
                        </span>
                        <span className="text-xs font-bold text-slate-100">{ev.title}</span>
                      </div>
                      <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-400">
                        <span className="px-2 py-0.5 rounded bg-slate-900">Layer: {ev.source_layer}</span>
                        <span className="px-2 py-0.5 rounded bg-slate-900">Engine: {ev.engine_name}</span>
                        <span className="text-cobalt-400">Conf: {Math.round(ev.confidence * 100)}%</span>
                      </div>
                    </div>
                    <p className="text-xs text-slate-300 mt-1">{ev.description}</p>
                    {ev.raw_indicator && (
                      <div className="mt-2 p-2 rounded bg-slate-900/80 text-[11px] font-mono text-amber-300 break-all border border-slate-800">
                        <span className="text-slate-400 mr-2">Indicator:</span>
                        {ev.raw_indicator}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400 italic">No high or critical anomalies identified during inspection.</p>
            )}
          </div>

          {/* Sections 17 & 18: Contradictory & Reassuring Observations */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Section 17 */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400 block mb-2">
                Section 17 · Contradictory Signals
              </span>
              {report.contradictory_signals.length > 0 ? (
                <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside">
                  {report.contradictory_signals.map((sig, i) => (
                    <li key={i}>{sig}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-400">No notable cross-layer contradictory signals observed.</p>
              )}
            </div>

            {/* Section 18 */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 block mb-2">
                Section 18 · Safe or Reassuring Observations
              </span>
              {report.safe_or_reassuring_observations.length > 0 ? (
                <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside">
                  {report.safe_or_reassuring_observations.map((sig, i) => (
                    <li key={i}>{sig}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-400">No reassuring signals (e.g. established age, EV cert) identified.</p>
              )}
            </div>
          </div>

          {/* Section 19: Missing Information (Truthful degradation) */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-2">
              Section 19 · Missing Information & Verification Boundaries
            </span>
            <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
              {report.missing_information.map((item, i) => (
                <li key={i}>{item}</li>
              ))}
              {report.missing_information.length === 0 && (
                <li>All primary configured telemetry checks completed successfully.</li>
              )}
            </ul>
          </div>

          {/* Section 20: Recommended Action Plan */}
          <div className="bg-cobalt-950/40 border border-cobalt-800/60 rounded-xl p-5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-cobalt-300 block mb-2">
              Section 20 · Actionable Security Recommendations
            </span>
            <div className="space-y-2">
              {report.recommended_action_plan.map((action, i) => (
                <div key={i} className="flex items-start space-x-2 text-xs text-slate-200">
                  <span className="font-mono text-cobalt-400 font-bold">{i + 1}.</span>
                  <span>{action}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: CORRELATION GRAPH */}
      {activeTab === 'graph' && (
        <EvidenceGraphView graph={report.intelligence_graph} />
      )}

      {/* TAB 3: 16 DETECTION ENGINES */}
      {activeTab === 'engines' && (
        <div className="space-y-3">
          <div className="text-xs text-slate-400 px-1 mb-2">
            Section 9 · Comprehensive Multi-Engine Execution Telemetry (16 Autonomous Detection Engines)
          </div>
          {report.detection_engine_results.map((engine) => {
            const isExp = expandedEngine === engine.engine_name;
            return (
              <div
                key={engine.engine_name}
                className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden"
              >
                <div
                  onClick={() => setExpandedEngine(isExp ? null : engine.engine_name)}
                  className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-800/40 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                    <span className="text-xs font-bold text-slate-200">{engine.engine_name}</span>
                    <span className="text-[10px] font-mono text-slate-400">
                      {engine.execution_time_ms}ms · Risk: {engine.risk_contribution}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-slate-400 truncate max-w-md hidden md:block">
                      {engine.summary}
                    </span>
                    {isExp ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                  </div>
                </div>

                {isExp && (
                  <div className="p-4 bg-slate-950/60 border-t border-slate-800 space-y-3">
                    <div>
                      <span className="text-[10px] font-mono uppercase text-slate-400">Engine Findings</span>
                      <ul className="mt-1 text-xs text-slate-300 space-y-1 list-disc list-inside">
                        {engine.findings.map((f, i) => (
                          <li key={i}>{f}</li>
                        ))}
                      </ul>
                    </div>
                    {engine.metadata && Object.keys(engine.metadata).length > 0 && (
                      <div>
                        <span className="text-[10px] font-mono uppercase text-slate-400">Technical Metadata</span>
                        <pre className="mt-1 p-3 rounded bg-slate-900 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-40 border border-slate-800">
                          {JSON.stringify(engine.metadata, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* TAB 4: TECHNICAL INFRASTRUCTURE */}
      {activeTab === 'technical' && (
        <div className="space-y-6">
          {/* Section 10: Threat Intelligence Sources */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 block mb-3">
              Section 10 · External Threat Intelligence Sources ({report.threat_intelligence_sources.length})
            </span>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {report.threat_intelligence_sources.map((src, i) => (
                <div key={i} className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">{src.provider_name}</span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                        src.match_status
                          ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                          : src.provider_status === 'Authentication required'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}
                    >
                      {src.provider_status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-2">
                    {src.findings[0] || src.error_message || 'Telemetry query complete.'}
                  </p>
                  {src.latency_ms !== null && src.latency_ms !== undefined && (
                    <span className="text-[10px] font-mono text-slate-400 block mt-2">
                      Latency: {src.latency_ms}ms
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Section 11 & 12: Domain & DNS Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 block mb-3">
                Section 11 · Domain Registration & RDAP
              </span>
              <pre className="p-3 rounded bg-slate-950 text-xs font-mono text-slate-300 overflow-x-auto border border-slate-800">
                {JSON.stringify(report.domain_information, null, 2)}
              </pre>
            </div>
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200 block mb-3">
                Section 12 · Technical DNS & TLS Infrastructure
              </span>
              <pre className="p-3 rounded bg-slate-950 text-xs font-mono text-slate-300 overflow-x-auto border border-slate-800">
                {JSON.stringify(report.technical_indicators, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: COUNTERFACTUAL SIMULATOR */}
      {activeTab === 'counterfactual' && (
        <CounterfactualSimulator
          investigationId={report.investigation_id}
          originalRiskScore={report.risk_score}
          originalVerdict={report.overall_verdict}
        />
      )}
    </div>
  );
};
