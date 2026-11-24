export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type InvestigationType = 'website' | 'url' | 'email' | 'message' | 'job_offer';

export type VerdictCategory = 
  | 'No Significant Risk Detected'
  | 'Low Risk'
  | 'Suspicious'
  | 'High Risk / Likely Malicious'
  | 'Confirmed Malicious'
  | 'Inconclusive / Insufficient Information';

export interface EvidenceItem {
  id: string;
  engine_name: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  raw_indicator?: string;
  confidence: number;
  source_layer: string;
  category: string;
}

export interface EngineExecutionResult {
  engine_name: string;
  executed: boolean;
  execution_time_ms: number;
  status: string;
  summary: string;
  risk_contribution: number;
  findings: string[];
  evidence: EvidenceItem[];
  metadata: Record<string, any>;
  error?: string;
}

export interface ThreatIntelResult {
  provider_name: string;
  provider_status: string;
  query_timestamp: string;
  query_type: string;
  target: string;
  match_status: boolean;
  findings: string[];
  confidence?: number;
  source_reference?: string;
  latency_ms?: number;
  error_message?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  node_type: string;
  risk_level: string;
  details: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
  relationship_type: string;
  is_inferred: boolean;
  weight: number;
}

export interface IntelligenceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CounterfactualVerdictResult {
  original_risk_score: number;
  simulated_risk_score: number;
  original_verdict: VerdictCategory;
  simulated_verdict: VerdictCategory;
  delta_explanation: string;
  divergent_factors: string[];
}

export interface InvestigationReport {
  investigation_id: string;
  submitted_entity: string;
  investigation_type: InvestigationType;
  overall_verdict: VerdictCategory;
  risk_score: number;
  assessment_confidence: number;
  analysis_coverage: number;
  executive_summary: string;
  detection_engine_results: EngineExecutionResult[];
  threat_intelligence_sources: ThreatIntelResult[];
  domain_information: Record<string, any>;
  technical_indicators: Record<string, any>;
  website_identity_findings: Record<string, any>;
  email_authentication_findings?: Record<string, any>;
  evidence_excerpts: EvidenceItem[];
  correlated_findings: string[];
  contradictory_signals: string[];
  safe_or_reassuring_observations: string[];
  missing_information: string[];
  recommended_action_plan: string[];
  investigation_timestamp: string;
  algorithm_version: string;
  intelligence_graph: IntelligenceGraph;
  counterfactual_insights: string[];
  limitations: string[];
}

export interface JudgeScenario {
  id: string;
  title: string;
  type: InvestigationType;
  description: string;
  input_data: Record<string, any>;
  expected_verdict: string;
  highlights: string[];
}

export interface ProviderInfo {
  name: string;
  category: string;
  type: string;
  status: string;
  latency: string;
  attribution: string;
}

export interface DashboardSummary {
  total_investigations: number;
  threat_breakdown: {
    critical_or_high_risk: number;
    suspicious: number;
    minimal_or_low_risk: number;
  };
  average_risk_score: number;
  active_engines: number;
  recent_investigations: any[];
}
