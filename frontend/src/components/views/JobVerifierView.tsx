import React, { useState } from 'react';
import { Briefcase, Shield, ArrowRight, RefreshCw, AlertCircle, DollarSign } from 'lucide-react';
import { api } from '../../services/api';
import { InvestigationReport } from '../../types';

interface JobVerifierProps {
  onInvestigationComplete: (report: InvestigationReport) => void;
}

export const JobVerifierView: React.FC<JobVerifierProps> = ({ onInvestigationComplete }) => {
  const [companyName, setCompanyName] = useState('');
  const [recruiterName, setRecruiterName] = useState('');
  const [recruiterEmail, setRecruiterEmail] = useState('');
  const [jobTitle, setJobTitle] = useState('');
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [offerText, setOfferText] = useState('');
  const [paymentRequested, setPaymentRequested] = useState(false);
  const [paymentAmount, setPaymentAmount] = useState('');
  const [interviewPlatform, setInterviewPlatform] = useState('Telegram');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!companyName.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const report = await api.investigateJobOffer({
        company_name: companyName,
        recruiter_name: recruiterName,
        recruiter_email: recruiterEmail,
        job_title: jobTitle,
        website_url: websiteUrl,
        offer_text: offerText,
        payment_requested: paymentRequested,
        payment_amount: paymentAmount,
        interview_platform: interviewPlatform
      });
      onInvestigationComplete(report);
    } catch (err: any) {
      setError(err.message || 'Failed to verify recruitment authenticity');
    } finally {
      setLoading(false);
    }
  };

  const loadSampleScam = () => {
    setCompanyName('Vertex Global Freight Inc.');
    setRecruiterName('Sarah Jenkins');
    setRecruiterEmail('sarah.jenkins.vertex@gmail.com');
    setJobTitle('Remote Data Processing Specialist');
    setWebsiteUrl('https://vertex-freight-careers.net');
    setOfferText('Congratulations! Your application has been immediately approved ($55/hr). You will receive enterprise workstation hardware; however, you must remit a $150 refundable processing deposit before shipping.');
    setPaymentRequested(true);
    setPaymentAmount('$150 Refundable Security Deposit');
    setInterviewPlatform('Telegram');
  };

  const loadLegitSample = () => {
    setCompanyName('Google LLC');
    setRecruiterName('Google Technical Staffing');
    setRecruiterEmail('recruiting@google.com');
    setJobTitle('Software Engineer');
    setWebsiteUrl('https://careers.google.com');
    setOfferText('Thank you for speaking with our engineering recruiter. We would like to invite you for virtual interviews via Google Meet. There are never any fees associated with Google recruitment.');
    setPaymentRequested(false);
    setPaymentAmount('');
    setInterviewPlatform('Google Meet');
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      <div>
        <div className="flex items-center space-x-2 text-xs font-mono uppercase text-amber-400 mb-1">
          <Briefcase className="w-3.5 h-3.5" />
          <span>Workspace E · Global Job &amp; Organization Authenticity Intelligence</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100">Verify Job &amp; Internship Offers</h1>
        <p className="text-xs text-slate-400 mt-1">
          Never assume an offer is legitimate simply because the company exists.
          Investigate recruiter email alignment, upfront fee demands, chat-app interviews, and official domain records.
        </p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Company / Organization Name *
              </label>
              <input
                type="text"
                required
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder="e.g. Microsoft, Google, or Unknown Freight LLC"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs focus:border-amber-500 outline-none"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Position / Job Title
              </label>
              <input
                type="text"
                value={jobTitle}
                onChange={(e) => setJobTitle(e.target.value)}
                placeholder="e.g. Remote Data Entry or QA Analyst"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs focus:border-amber-500 outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Recruiter Email Address
              </label>
              <input
                type="text"
                value={recruiterEmail}
                onChange={(e) => setRecruiterEmail(e.target.value)}
                placeholder="e.g. hr.company@gmail.com or recruiter@official.com"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:border-amber-500 outline-none"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Company Website URL
              </label>
              <input
                type="text"
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
                placeholder="e.g. https://company-careers.net"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:border-amber-500 outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Interview / Screening Platform
              </label>
              <input
                type="text"
                value={interviewPlatform}
                onChange={(e) => setInterviewPlatform(e.target.value)}
                placeholder="e.g. Telegram, WhatsApp, Google Meet, Zoom"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs focus:border-amber-500 outline-none"
              />
            </div>

            <div className="flex flex-col justify-end">
              <label className="flex items-center space-x-2.5 p-2 rounded-lg bg-slate-950 border border-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={paymentRequested}
                  onChange={(e) => setPaymentRequested(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-700 text-amber-500 focus:ring-amber-500"
                />
                <span className="text-xs font-medium text-slate-200">
                  Did recruiter demand upfront payment / deposit?
                </span>
              </label>
            </div>
          </div>

          {paymentRequested && (
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
              <label className="text-xs font-semibold text-amber-300 block mb-1">
                Demanded Payment Amount / Reason:
              </label>
              <input
                type="text"
                value={paymentAmount}
                onChange={(e) => setPaymentAmount(e.target.value)}
                placeholder="e.g. $150 refundable training deposit or hardware courier fee"
                className="w-full px-3 py-1.5 rounded bg-slate-950 border border-amber-500/40 text-amber-200 text-xs font-mono"
              />
            </div>
          )}

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">
              Offer Letter Excerpt or Invitation Text
            </label>
            <textarea
              rows={4}
              value={offerText}
              onChange={(e) => setOfferText(e.target.value)}
              placeholder="Paste job description, selection letter, or interview instructions..."
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-sans focus:border-amber-500 outline-none"
            />
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-start space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <div className="flex space-x-3 text-xs font-mono">
              <button
                type="button"
                onClick={loadSampleScam}
                className="text-amber-400 hover:text-amber-300 underline"
              >
                Load Sample Recruitment Scam
              </button>
              <button
                type="button"
                onClick={loadLegitSample}
                className="text-slate-400 hover:text-slate-200 underline"
              >
                Load Legitimate Corporate Offer
              </button>
            </div>

            <button
              type="submit"
              disabled={loading || !companyName.trim()}
              className="px-5 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-all disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <span>Verify Offer</span>}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
