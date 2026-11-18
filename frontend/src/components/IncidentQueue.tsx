import React, { useState } from 'react';
import { IncidentSummary, Severity } from '../types';
import { AlertCircle, Clock, ShieldAlert, CheckCircle2, ChevronRight, Filter } from 'lucide-react';

interface IncidentQueueProps {
  incidents: IncidentSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export const IncidentQueue: React.FC<IncidentQueueProps> = ({
  incidents,
  selectedId,
  onSelect,
}) => {
  const [filter, setFilter] = useState<'all' | 'pending' | 'critical'>('all');

  const filtered = incidents.filter((inc) => {
    if (filter === 'pending') return inc.status === 'awaiting_review' || inc.pending_action_count > 0;
    if (filter === 'critical') return inc.severity === 'Critical' || inc.severity === 'High';
    return true;
  });

  const getSeverityStyle = (severity?: Severity) => {
    switch (severity) {
      case 'Critical':
        return 'bg-red-500/10 border-red-500/30 text-red-400 font-semibold';
      case 'High':
        return 'bg-orange-500/10 border-orange-500/30 text-orange-400 font-semibold';
      case 'Medium':
        return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
      case 'Low':
      default:
        return 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
    }
  };

  const getStatusBadge = (status: string, pendingCount: number) => {
    if (status === 'awaiting_review' || pendingCount > 0) {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-medium bg-amber-950/80 text-amber-400 border border-amber-800">
          <Clock className="w-2.5 h-2.5 animate-spin" />
          <span>Awaiting Review ({pendingCount})</span>
        </span>
      );
    }
    if (status === 'resolved') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800">
          <CheckCircle2 className="w-2.5 h-2.5" />
          <span>Resolved</span>
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-blue-950/80 text-blue-400 border border-blue-800">
        Analyzing
      </span>
    );
  };

  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-full">
      {/* Header and Filter */}
      <div className="p-3.5 border-b border-slate-800 bg-slate-900/80 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-blue-400" />
          <h2 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
            Incident Queue ({filtered.length})
          </h2>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center space-x-1 text-[11px]">
          <button
            onClick={() => setFilter('all')}
            className={`px-2 py-1 rounded transition ${filter === 'all' ? 'bg-blue-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'}`}
          >
            All
          </button>
          <button
            onClick={() => setFilter('pending')}
            className={`px-2 py-1 rounded transition ${filter === 'pending' ? 'bg-amber-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Needs Review
          </button>
          <button
            onClick={() => setFilter('critical')}
            className={`px-2 py-1 rounded transition ${filter === 'critical' ? 'bg-red-600 text-white font-medium' : 'text-slate-400 hover:text-slate-200'}`}
          >
            High/Crit
          </button>
        </div>
      </div>

      {/* Incident List */}
      <div className="divide-y divide-slate-800/60 overflow-y-auto flex-1">
        {filtered.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">
            No incidents matching filter. Click "Simulate Attack" to generate events.
          </div>
        ) : (
          filtered.map((inc) => {
            const isSelected = inc.id === selectedId;
            const timeAgo = new Date(inc.created_at).toLocaleTimeString();

            return (
              <div
                key={inc.id}
                onClick={() => onSelect(inc.id)}
                className={`p-3.5 transition cursor-pointer flex flex-col space-y-2 border-l-4 ${
                  isSelected
                    ? 'bg-slate-800/90 border-l-blue-500 shadow-md'
                    : 'hover:bg-slate-800/40 border-l-transparent'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center space-x-2">
                    <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded border ${getSeverityStyle(inc.severity)}`}>
                      {inc.severity || 'TBD'}
                    </span>
                    <span className="text-xs font-semibold text-slate-200 tracking-tight font-mono">
                      {inc.incident_type ? inc.incident_type.replace('_', ' ').toUpperCase() : 'INCIDENT'}
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">{timeAgo}</span>
                </div>

                <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">
                  {inc.summary || 'Incident processing in agent pipeline...'}
                </p>

                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono bg-slate-950 px-1.5 py-0.5 rounded text-slate-400 border border-slate-800">
                      {inc.ioc_count} IOCs
                    </span>
                    <span className="font-mono bg-slate-950 px-1.5 py-0.5 rounded text-slate-400 border border-slate-800">
                      {inc.action_count} Actions
                    </span>
                  </div>
                  {getStatusBadge(inc.status, inc.pending_action_count)}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
