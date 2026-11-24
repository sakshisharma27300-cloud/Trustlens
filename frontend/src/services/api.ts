import { 
  InvestigationReport, CounterfactualVerdictResult, 
  JudgeScenario, ProviderInfo, DashboardSummary 
} from '../types';

const API_BASE = '/api/v1';

export const api = {
  // 1. Website Investigator
  async investigateWebsite(url: string, deepInspection: boolean = true): Promise<InvestigationReport> {
    const res = await fetch(`${API_BASE}/investigate/website`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, deep_inspection: deepInspection })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    return res.json();
  },

  // 2. URL Threat Scanner
  async investigateURL(url: string): Promise<InvestigationReport> {
    const res = await fetch(`${API_BASE}/investigate/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    return res.json();
  },

  // 3. Email Forensics
  async investigateEmail(data: {
    email_address?: string;
    sender_name?: string;
    subject?: string;
    body?: string;
    raw_headers?: string;
  }): Promise<InvestigationReport> {
    const res = await fetch(`${API_BASE}/investigate/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    return res.json();
  },

  // 4. Message Analyzer
  async investigateMessage(content: string, channel: string = 'general'): Promise<InvestigationReport> {
    const res = await fetch(`${API_BASE}/investigate/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, channel })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    return res.json();
  },

  // 5. Job & Organization Verifier
  async investigateJobOffer(data: {
    company_name: string;
    recruiter_name?: string;
    recruiter_email?: string;
    job_title?: string;
    website_url?: string;
    offer_text?: string;
    payment_requested?: boolean;
    payment_amount?: string;
    interview_platform?: string;
  }): Promise<InvestigationReport> {
    const res = await fetch(`${API_BASE}/investigate/job-offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    return res.json();
  },

  // Counterfactual Simulator
  async simulateCounterfactual(investigationId: string, modifiedParams: Record<string, any>): Promise<CounterfactualVerdictResult> {
    const res = await fetch(`${API_BASE}/counterfactual/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        investigation_id: investigationId,
        modified_parameters: modifiedParams
      })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    return res.json();
  },

  // History
  async getInvestigations(limit: number = 50): Promise<any[]> {
    const res = await fetch(`${API_BASE}/investigations?limit=${limit}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  async getInvestigationById(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/investigations/${id}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  async deleteInvestigation(id: string): Promise<boolean> {
    const res = await fetch(`${API_BASE}/investigations/${id}`, { method: 'DELETE' });
    return res.ok;
  },

  // Provider & System Health
  async getProviders(): Promise<ProviderInfo[]> {
    const res = await fetch(`${API_BASE}/intelligence/providers`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  async getDashboard(): Promise<DashboardSummary> {
    const res = await fetch(`${API_BASE}/dashboard`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  async getScenarios(): Promise<JudgeScenario[]> {
    const res = await fetch(`${API_BASE}/scenarios`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },

  async getBenchmarks(): Promise<any> {
    const res = await fetch(`${API_BASE}/benchmark`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }
};
