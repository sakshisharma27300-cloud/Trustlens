import React from 'react';
import { BookOpen, ShieldCheck, AlertOctagon, PhoneCall, Globe, ExternalLink, HelpCircle } from 'lucide-react';

export const LearningCenterView: React.FC = () => {
  const hotlines = [
    { country: 'United States', agency: 'FBI Internet Crime Complaint Center (IC3)', link: 'https://www.ic3.gov' },
    { country: 'United Kingdom', agency: 'Action Fraud & National Cyber Security Centre', link: 'https://www.actionfraud.police.uk' },
    { country: 'European Union', agency: 'Europol European Cybercrime Centre (EC3)', link: 'https://www.europol.europa.eu' },
    { country: 'India', agency: 'National Cyber Crime Reporting Portal (Helpline: 1930)', link: 'https://cybercrime.gov.in' },
    { country: 'Australia', agency: 'Scamwatch / Australian Cyber Security Centre', link: 'https://www.scamwatch.gov.au' },
    { country: 'Canada', agency: 'Canadian Anti-Fraud Centre (CAFC)', link: 'https://www.antifraudcentre-centreantifraude.ca' },
    { country: 'Singapore', agency: 'ScamShield & Singapore Police Force', link: 'https://www.scamshield.org.sg' }
  ];

  const scamTaxonomy = [
    {
      title: 'Digital Arrest & Video Extortion',
      desc: 'Criminals masquerade as police or customs officials asserting fake narcotics or money laundering warrants. Victims are coerced into remaining on continuous Skype/WhatsApp video calls and wire transferring "clearance funds".',
      redFlags: ['Urgent demand to stay on video call alone', 'Fake arrest warrant or supreme court letterhead', 'Demand to transfer money for "verification"']
    },
    {
      title: 'Advance-Fee Recruitment Fraud',
      desc: 'Fraudulent recruiters issue immediate appointment letters with exorbitant remote salaries ($50-80/hr) and subsequently demand upfront "refundable security deposits" for software or courier delivery.',
      redFlags: ['Recruiter contacts via free @gmail.com webmail', 'Screening conducted solely over Telegram chat', 'Upfront payment demanded for hardware, training, or onboarding']
    },
    {
      title: 'Fake Courier & Customs Redelivery',
      desc: 'Automated SMS or WhatsApp messages alert victims that an international package is detained due to a small unpaid customs duty (e.g. $1.85), leading to deceptive lookalike payment forms that steal credit cards.',
      redFlags: ['Unsolicited tracking link on discount TLD (.top, .xyz)', 'Small arbitrary fee demanded to unlock parcels', 'Urgent 24-hour expiration countdown']
    },
    {
      title: 'OTP Interception & Support Impersonation',
      desc: 'Attackers impersonate bank anti-fraud officers alerting victims of suspicious transactions, tricking them into reading aloud multi-factor authentication SMS codes.',
      redFlags: ['Caller requests SMS one-time password (OTP)', 'Caller creates panic about unauthorized debit charges', 'Caller asks victim to install AnyDesk or TeamViewer']
    }
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-8 pb-12">
      <div>
        <div className="flex items-center space-x-2 text-xs font-mono uppercase text-purple-400 mb-1">
          <BookOpen className="w-3.5 h-3.5" />
          <span>Section 11 · Global Digital Trust Knowledge Base</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100">Security Learning Center &amp; Scam Taxonomy</h1>
        <p className="text-xs text-slate-400 mt-1">
          Comprehensive guides on global fraud patterns, psychological coercion vectors, and official incident response channels.
        </p>
      </div>

      {/* Scam Taxonomy */}
      <div>
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-4">
          Prevalent International Scam Typologies
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scamTaxonomy.map((scam, idx) => (
            <div key={idx} className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <h3 className="text-sm font-bold text-slate-100">{scam.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{scam.desc}</p>
              <div>
                <span className="text-[10px] font-mono uppercase text-rose-400 block mb-1">Critical Red Flags:</span>
                <ul className="text-xs text-slate-300 space-y-1 list-disc list-inside">
                  {scam.redFlags.map((rf, i) => (
                    <li key={i}>{rf}</li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Official Hotlines & Reporting Guidance */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-2 flex items-center space-x-2">
          <PhoneCall className="w-4 h-4 text-emerald-400" />
          <span>Official Regional Cybercrime Reporting Portals</span>
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          If you or your organization encounter active cyber threats, report details directly to authorized law enforcement agencies.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {hotlines.map((h, i) => (
            <a
              key={i}
              href={h.link}
              target="_blank"
              rel="noopener noreferrer"
              className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 flex flex-col justify-between group transition-colors"
            >
              <div>
                <span className="text-[10px] font-mono uppercase text-emerald-400 font-bold block mb-1">
                  {h.country}
                </span>
                <span className="text-xs font-semibold text-slate-200 group-hover:text-emerald-300 transition-colors">
                  {h.agency}
                </span>
              </div>
              <div className="mt-3 flex items-center space-x-1 text-[11px] font-mono text-slate-400">
                <span>Official Portal</span>
                <ExternalLink className="w-3 h-3 text-slate-400" />
              </div>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
};
