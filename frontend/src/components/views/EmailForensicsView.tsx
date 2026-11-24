import React, { useState } from 'react';
import { Mail, Shield, ArrowRight, RefreshCw, AlertCircle, FileText, CheckCircle } from 'lucide-react';
import { api } from '../../services/api';
import { InvestigationReport } from '../../types';

interface EmailForensicsProps {
  onInvestigationComplete: (report: InvestigationReport) => void;
}

export const EmailForensicsView: React.FC<EmailForensicsProps> = ({ onInvestigationComplete }) => {
  const [emailAddress, setEmailAddress] = useState('');
  const [senderName, setSenderName] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [rawHeaders, setRawHeaders] = useState('');
  const [showHeaders, setShowHeaders] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailAddress.trim() && !subject.trim() && !body.trim() && !rawHeaders.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const report = await api.investigateEmail({
        email_address: emailAddress,
        sender_name: senderName,
        subject,
        body,
        raw_headers: rawHeaders
      });
      onInvestigationComplete(report);
    } catch (err: any) {
      setError(err.message || 'Failed to inspect email');
    } finally {
      setLoading(false);
    }
  };

  const loadSamplePhish = () => {
    setEmailAddress('security@paypal-security-update.com');
    setSenderName('PayPal Security Team');
    setSubject('Urgent: Your account has been temporarily restricted due to unauthorized login');
    setBody('Dear valued customer, We observed logins from unfamiliar IP 198.51.100.22. Please click here to verify your credentials: https://paypal-security-update.com/restore. Failure to do so within 12 hours will result in permanent suspension.');
    setRawHeaders(`From: PayPal Security Team <security@paypal-security-update.com>
Reply-To: phishcollector99@yandex.com
To: user@example.com
Subject: Urgent: Your account has been temporarily restricted due to unauthorized login
Authentication-Results: mx.google.com; spf=fail (google.com: domain of security@paypal-security-update.com does not designate 198.51.100.25 as permitted sender) smtp.mailfrom=security@paypal-security-update.com; dkim=fail (bad signature); dmarc=fail (p=REJECT) header.from=paypal-security-update.com
Received: from rogue-relay.vps.net (198.51.100.25) by mx.google.com`);
    setShowHeaders(true);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      <div>
        <div className="flex items-center space-x-2 text-xs font-mono uppercase text-indigo-400 mb-1">
          <Mail className="w-3.5 h-3.5" />
          <span>Workspace B · Global Email Forensics</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100">Investigate Suspicious Emails</h1>
        <p className="text-xs text-slate-400 mt-1">
          Parses RFC 822 email headers, extracts genuine SPF/DKIM/DMARC authentication results,
          traces relay hops, detects display name impersonation, and uncovers Reply-To divergence.
        </p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Sender Email Address
              </label>
              <input
                type="text"
                value={emailAddress}
                onChange={(e) => setEmailAddress(e.target.value)}
                placeholder="e.g. service@paypal-security.com or hr@company.com"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:border-indigo-500 outline-none"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Display / Sender Name
              </label>
              <input
                type="text"
                value={senderName}
                onChange={(e) => setSenderName(e.target.value)}
                placeholder="e.g. PayPal Security or CEO Name"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs focus:border-indigo-500 outline-none"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">
              Email Subject Line
            </label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="e.g. Urgent verification required or Invoice Payment #889"
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs focus:border-indigo-500 outline-none"
            />
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">
              Email Body Content
            </label>
            <textarea
              rows={4}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Paste email text or message content here..."
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-sans focus:border-indigo-500 outline-none"
            />
          </div>

          <div>
            <button
              type="button"
              onClick={() => setShowHeaders(!showHeaders)}
              className="text-xs font-mono text-indigo-400 hover:text-indigo-300 flex items-center space-x-1"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>{showHeaders ? 'Hide RFC 822 Headers' : '+ Paste Original Raw Email Headers (SPF, DKIM, DMARC)'}</span>
            </button>

            {showHeaders && (
              <div className="mt-2">
                <textarea
                  rows={5}
                  value={rawHeaders}
                  onChange={(e) => setRawHeaders(e.target.value)}
                  placeholder="Paste RFC 822 header block from email client (Authentication-Results, Received-SPF, Received, Reply-To)..."
                  className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 text-[11px] font-mono focus:border-indigo-500 outline-none"
                />
              </div>
            )}
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-start space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <button
              type="button"
              onClick={loadSamplePhish}
              className="text-xs font-mono text-slate-400 hover:text-slate-200 underline"
            >
              Load Sample Spoofed Email with Header Failures
            </button>

            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-all disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <span>Run Email Forensics</span>}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
