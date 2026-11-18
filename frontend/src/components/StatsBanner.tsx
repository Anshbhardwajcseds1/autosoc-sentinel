import React from 'react';
import { ShieldAlert, Clock, CheckCheck, AlertOctagon, Activity, ShieldCheck } from 'lucide-react';
import { DashboardStats } from '../types';

interface StatsBannerProps {
  stats: DashboardStats | null;
}

export const StatsBanner: React.FC<StatsBannerProps> = ({ stats }) => {
  if (!stats) return null;

  const mttrDisplay = stats.mean_time_to_respond_seconds !== null && stats.mean_time_to_respond_seconds !== undefined
    ? `${stats.mean_time_to_respond_seconds}s`
    : 'Pending';

  return (
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-3.5 px-6 pt-5 pb-2">
      {/* Incidents Today */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Incidents Today</div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1">{stats.incidents_today}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Total logged: {stats.total_incidents}</div>
        </div>
        <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg">
          <Activity className="w-5 h-5" />
        </div>
      </div>

      {/* Open / Awaiting Review */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Open Incidents</div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{stats.open_incidents}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Awaiting human review</div>
        </div>
        <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-lg">
          <ShieldAlert className="w-5 h-5" />
        </div>
      </div>

      {/* Mean Time To Respond */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Mean Time to Respond</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{mttrDisplay}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Creation to containment</div>
        </div>
        <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg">
          <Clock className="w-5 h-5" />
        </div>
      </div>

      {/* Approval Rate */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">Action Approval Rate</div>
          <div className="text-2xl font-bold font-mono text-blue-400 mt-1">{stats.approval_rate}%</div>
          <div className="text-[11px] text-slate-500 mt-0.5">{stats.approved_actions} approved / {stats.rejected_actions} rejected</div>
        </div>
        <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg">
          <CheckCheck className="w-5 h-5" />
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-3.5 col-span-2 lg:col-span-1">
        <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400 mb-2">Severity Breakdown</div>
        <div className="flex items-center space-x-1.5 font-mono text-xs">
          <span className="px-2 py-0.5 rounded bg-red-950/80 border border-red-800 text-red-400 font-semibold" title="Critical">
            C:{stats.critical_incidents}
          </span>
          <span className="px-2 py-0.5 rounded bg-orange-950/80 border border-orange-800 text-orange-400 font-semibold" title="High">
            H:{stats.high_incidents}
          </span>
          <span className="px-2 py-0.5 rounded bg-amber-950/80 border border-amber-800 text-amber-400 font-semibold" title="Medium">
            M:{stats.medium_incidents}
          </span>
          <span className="px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-400 font-semibold" title="Low">
            L:{stats.low_incidents}
          </span>
        </div>
      </div>
    </div>
  );
};
