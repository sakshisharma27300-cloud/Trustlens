import React, { useState } from 'react';
import { MessageSquare, Shield, ArrowRight, RefreshCw, AlertCircle, Languages } from 'lucide-react';
import { api } from '../../services/api';
import { InvestigationReport } from '../../types';

interface MessageAnalyzerProps {
  onInvestigationComplete: (report: InvestigationReport) => void;
}

export const MessageAnalyzerView: React.FC<MessageAnalyzerProps> = ({ onInvestigationComplete }) => {
  const [content, setContent] = useState('');
  const [channel, setChannel] = useState('whatsapp');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const report = await api.investigateMessage(content, channel);
      onInvestigationComplete(report);
    } catch (err: any) {
      setError(err.message || 'Failed to inspect message');
    } finally {
      setLoading(false);
    }
  };

  const sampleScams = [
    {
      label: 'Digital Arrest Scam (Hindi/English)',
      channel: 'whatsapp',
      text: 'URGENT NOTICE: आपके नाम पर मुंबई कस्टम्स में एक पार्सल ज़ब्त किया गया है जिसमें अवैध ड्रग्स पाए गए हैं। आपके खिलाफ डिजिटल अरेस्ट वारंट जारी किया गया है। तुरंत इस स्काइप आईडी पर संपर्क करें और किसी से बात न करें।'
    },
    {
      label: 'Courier Impersonation (DHL/FedEx)',
      channel: 'sms',
      text: 'DHL Express: Your shipment #847291 could not be delivered due to an unpaid customs fee of $1.85. Confirm delivery details at https://dhl-express-redelivery-fee.top within 24h.'
    },
    {
      label: 'Crypto Airdrop / Guaranteed Return',
      channel: 'telegram',
      text: 'Binance VIP Signal Group: Guaranteed daily profit 25%! Send 0.05 BTC to our automated smart contract mining pool and receive 0.15 BTC return in 24 hours. 100% risk free passive income.'
    },
    {
      label: 'Fake Refund & Remote Support',
      channel: 'email',
      text: 'Amazon Order #8391: We accidentally refunded $500 instead of $50 to your account. Please install AnyDesk immediately and connect with our senior billing officer to return the remaining amount.'
    }
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      <div>
        <div className="flex items-center space-x-2 text-xs font-mono uppercase text-emerald-400 mb-1">
          <MessageSquare className="w-3.5 h-3.5" />
          <span>Workspace D · Global Message & Social Engineering Detector</span>
        </div>
        <h1 className="text-2xl font-bold text-slate-100">Analyze Messages for Psychological Manipulation</h1>
        <p className="text-xs text-slate-400 mt-1">
          Detects international fraud typologies: Digital Arrest, Courier scams, OTP elicitation,
          crypto doubling, and coercive urgency across English, Spanish, French, German, Hindi, and more.
        </p>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-300">Originating Channel:</span>
            {['whatsapp', 'sms', 'telegram', 'linkedin', 'email', 'instagram'].map((ch) => (
              <button
                key={ch}
                type="button"
                onClick={() => setChannel(ch)}
                className={`px-3 py-1 rounded-md text-xs font-mono uppercase transition-colors ${
                  channel === ch
                    ? 'bg-emerald-600 text-white font-bold'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {ch}
              </button>
            ))}
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1.5">
              Paste Complete Message or Communication Text
            </label>
            <textarea
              rows={5}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste SMS, WhatsApp message, Telegram broadcast, or direct message..."
              className="w-full px-4 py-3 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-sans focus:border-emerald-500 outline-none leading-relaxed"
            />
          </div>

          <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-400">
            <Languages className="w-3.5 h-3.5 text-emerald-400" />
            <span>Multilingual Awareness: Original scripts preserved; exact suspicious excerpts highlighted.</span>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-start space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={loading || !content.trim()}
              className="px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-all disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <span>Analyze Message</span>}
            </button>
          </div>
        </form>

        <div className="mt-6 pt-4 border-t border-slate-800">
          <span className="text-[11px] font-mono uppercase text-slate-400 block mb-2">
            Load Regional Scam Signatures:
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {sampleScams.map((scam, i) => (
              <button
                key={i}
                type="button"
                onClick={() => {
                  setContent(scam.text);
                  setChannel(scam.channel);
                }}
                className="p-2.5 text-left rounded bg-slate-800/60 hover:bg-slate-800 text-slate-300 text-xs border border-slate-700/80 transition-colors"
              >
                <span className="font-semibold text-emerald-400 block mb-0.5">{scam.label}</span>
                <span className="text-[11px] text-slate-400 line-clamp-2">{scam.text}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
