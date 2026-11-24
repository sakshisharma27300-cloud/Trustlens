import React, { useEffect, useState } from 'react';
import { History, Search, Trash2, ArrowRight, ShieldAlert, Filter, Clock } from 'lucide-react';
import { api } from '../../services/api';
import { InvestigationReport } from '../../types';

interface HistoryProps {
  onSelectReport: (report: InvestigationReport) => void;
}

export const HistoryView: React.FC<HistoryProps> = ({ onSelectReport }) => {
  const [records, setRecords] = useState<any[]>([]);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [loading, setLoading] = useState(true);

  const loadHistory = () => {
    setLoading(true);
    api.getInvestigations(50)
      .then(res => setRecords(res))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm('Delete this investigation record?')) {
      await api.deleteInvestigation(id);
      loadHistory();
    }
  };

  const filtered = records.filter(r => {
    const matchesSearch = r.entity.toLowerCase().includes(search.toLowerCase()) || 
                          r.summary?.toLowerCase().includes(search.toLowerCase());
    const matchesType = filterType === 'all' || r.type === filterType;
    return matchesSearch && matchesType;
  });

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono uppercase text-cobalt-400 mb-1">
            <History className="w-3.5 h-3.5" />
            <span>Audit &amp; Intelligence Archives</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100">Historical Investigation Log</h1>
          <p className="text-xs text-slate-400 mt-1">
            Review past investigations, examine forensic evidence, or compare threat patterns over time.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by URL, domain, or summary keywords..."
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200 outline-none focus:border-cobalt-500"
          />
        </div>

        <div className="flex items-center space-x-2 text-xs">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          {['all', 'website', 'url', 'email', 'message', 'job_offer'].map(t => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-2.5 py-1 rounded text-xs font-mono uppercase transition-colors ${
                filterType === t
                  ? 'bg-cobalt-600 text-white font-bold'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Records Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-xs text-slate-400 font-mono">
            Loading investigation records...
          </div>
        ) : filtered.length > 0 ? (
          <div className="divide-y divide-slate-800/80">
            {filtered.map((rec) => (
              <div
                key={rec.id}
                onClick={() => onSelectReport(rec.report)}
                className="p-4 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-800/30 cursor-pointer transition-colors"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                      {rec.type}
                    </span>
                    <span className="text-xs font-bold font-mono text-slate-100 hover:text-cobalt-300">
                      {rec.entity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 max-w-2xl line-clamp-1">
                    {rec.summary}
                  </p>
                </div>

                <div className="flex items-center space-x-4">
                  <div className="text-right">
                    <span className="text-xs font-mono block">
                      Risk: <strong className={rec.risk_score > 60 ? 'text-red-400' : 'text-emerald-400'}>{rec.risk_score}</strong>
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 flex items-center justify-end space-x-1">
                      <Clock className="w-3 h-3" />
                      <span>{new Date(rec.created_at).toLocaleDateString()}</span>
                    </span>
                  </div>

                  <button
                    onClick={(e) => handleDelete(rec.id, e)}
                    className="p-1.5 rounded hover:bg-red-500/20 text-slate-400 hover:text-red-400 transition-colors"
                    title="Delete record"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>

                  <ArrowRight className="w-4 h-4 text-slate-400" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-16 text-center text-xs text-slate-400 font-mono">
            No investigations match the specified criteria.
          </div>
        )}
      </div>
    </div>
  );
};
