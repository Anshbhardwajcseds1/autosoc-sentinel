import React, { useState } from 'react';
import {
  IncidentDetail as IncidentDetailType,
  ContainmentAction,
  Severity,
} from '../types';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  RotateCcw,
  AlertTriangle,
  Code2,
  Terminal,
  Activity,
  User,
  ExternalLink,
  Flame,
  FileText,
  History,
  CheckCheck,
} from 'lucide-react';

interface IncidentDetailProps {
  incident: IncidentDetailType | null;
  onApproveAction: (actionId: string, comment?: string) => Promise<void>;
  onRejectAction: (actionId: string, comment?: string) => Promise<void>;
  onRollbackAction: (actionId: string) => Promise<void>;
  onApproveAllRecommended: () => Promise<void>;
  isLoading: boolean;
}

export const IncidentDetail: React.FC<IncidentDetailProps> = ({
  incident,
  onApproveAction,
  onRejectAction,
  onRollbackAction,
  onApproveAllRecommended,
  isLoading,
}) => {
  const [activeTab, setActiveTab] = useState<'actions' | 'iocs' | 'timeline' | 'raw' | 'audit'>('actions');
  const [commentInputs, setCommentInputs] = useState<Record<string, string>>({});
  const [showCommands, setShowCommands] = useState<Record<string, boolean>>({});

  if (!incident) {
    return (
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl h-full flex flex-col items-center justify-center p-12 text-center text-slate-500">
        <ShieldAlert className="w-12 h-12 text-slate-700 mb-3" />
        <h3 className="text-base font-semibold text-slate-400">No Incident Selected</h3>
        <p className="text-xs text-slate-500 max-w-sm mt-1">
          Select an incident from the queue on the left or simulate a new security attack to inspect real-time agent containment.
        </p>
      </div>
    );
  }

  const handleCommentChange = (actionId: string, val: string) => {
    setCommentInputs((prev) => ({ ...prev, [actionId]: val }));
  };

  const toggleCommandView = (actionId: string) => {
    setShowCommands((prev) => ({ ...prev, [actionId]: !prev[actionId] }));
  };

  const getSeverityBadge = (severity?: Severity) => {
    switch (severity) {
      case 'Critical':
        return 'bg-red-950 border-red-700 text-red-400 animate-pulse';
      case 'High':
        return 'bg-orange-950 border-orange-700 text-orange-400';
      case 'Medium':
        return 'bg-amber-950 border-amber-700 text-amber-400';
      case 'Low':
      default:
        return 'bg-emerald-950 border-emerald-700 text-emerald-400';
    }
  };

  const getReputationColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-950/60 border-red-800';
    if (score >= 40) return 'text-amber-400 bg-amber-950/60 border-amber-800';
    return 'text-emerald-400 bg-emerald-950/60 border-emerald-800';
  };

  const pendingRecommendedCount = incident.actions.filter(
    (a) => a.is_recommended && a.status === 'pending'
  ).length;

  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-full">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 bg-slate-900/90">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <span
              className={`text-xs uppercase font-mono font-bold px-2.5 py-1 rounded border tracking-wider ${getSeverityBadge(
                incident.severity
              )}`}
            >
              {incident.severity || 'LOW'} SEVERITY
            </span>
            <span className="text-sm font-bold text-slate-100 font-mono tracking-tight">
              {incident.incident_type ? incident.incident_type.toUpperCase() : 'INCIDENT'}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              CONFIDENCE: {Math.round((incident.confidence || 0.8) * 100)}%
            </span>
          </div>

          {/* Action Batch Approval */}
          {pendingRecommendedCount > 0 && (
            <button
              onClick={() => onApproveAllRecommended()}
              disabled={isLoading}
              className="flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium text-xs px-3.5 py-2 rounded-lg shadow-md transition"
            >
              <CheckCheck className="w-4 h-4" />
              <span>Approve All Recommended ({pendingRecommendedCount})</span>
            </button>
          )}
        </div>

        {/* Summary */}
        <p className="text-xs text-slate-300 mt-2.5 leading-relaxed bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
          <strong className="text-slate-100">AI Assessment: </strong>
          {incident.summary}
        </p>

        {/* Navigation Tabs */}
        <div className="flex items-center space-x-1 mt-4 border-b border-slate-800 text-xs">
          <button
            onClick={() => setActiveTab('actions')}
            className={`px-3 py-2 border-b-2 font-medium transition flex items-center space-x-1.5 ${
              activeTab === 'actions'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Proposed Containment ({incident.actions.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('iocs')}
            className={`px-3 py-2 border-b-2 font-medium transition flex items-center space-x-1.5 ${
              activeTab === 'iocs'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>IOCs & Threat Intel ({incident.iocs.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`px-3 py-2 border-b-2 font-medium transition flex items-center space-x-1.5 ${
              activeTab === 'timeline'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Agent Reasoning Timeline ({incident.agent_steps.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`px-3 py-2 border-b-2 font-medium transition flex items-center space-x-1.5 ${
              activeTab === 'raw'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Raw Telemetry</span>
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-3 py-2 border-b-2 font-medium transition flex items-center space-x-1.5 ${
              activeTab === 'audit'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Audit Trail ({incident.audit_logs.length})</span>
          </button>
        </div>
      </div>

      {/* Tab Contents */}
      <div className="p-4 overflow-y-auto flex-1">
        {/* 1. Containment Actions Tab */}
        {activeTab === 'actions' && (
          <div className="space-y-4">
            <div className="bg-blue-950/30 border border-blue-900/50 p-2.5 rounded-lg text-xs text-blue-300 flex items-center space-x-2">
              <Terminal className="w-4 h-4 flex-shrink-0 text-blue-400" />
              <span>
                <strong>Human-in-the-Loop Safe Execution:</strong> Containment actions remain in dry-run mode. Approving an action executes it against the SOC Simulator engine and writes an immutable audit record.
              </span>
            </div>

            {incident.actions.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs">No containment actions required.</div>
            ) : (
              incident.actions.map((action) => {
                const commentVal = commentInputs[action.id] || '';
                const isCmdExpanded = showCommands[action.id] ?? false;

                return (
                  <div
                    key={action.id}
                    className={`bg-slate-950/70 border rounded-xl p-4 transition ${
                      action.status === 'executed_simulated'
                        ? 'border-emerald-800/80 bg-emerald-950/10'
                        : action.status === 'rejected'
                        ? 'border-slate-800 opacity-60'
                        : action.status === 'rolled_back'
                        ? 'border-amber-800/80 bg-amber-950/10'
                        : 'border-slate-800'
                    }`}
                  >
                    {/* Action Card Top Bar */}
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs font-bold text-slate-100 uppercase px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                          {action.action_type.replace('_', ' ')}
                        </span>
                        <span className="font-mono text-xs font-semibold text-blue-400 bg-blue-950/60 px-2 py-0.5 rounded border border-blue-900">
                          {action.target}
                        </span>
                        {action.is_recommended && (
                          <span className="text-[10px] uppercase font-bold text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                            ★ RECOMMENDED
                          </span>
                        )}
                        <span
                          className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                            action.risk_level === 'high'
                              ? 'text-red-400 bg-red-950'
                              : action.risk_level === 'medium'
                              ? 'text-amber-400 bg-amber-950'
                              : 'text-emerald-400 bg-emerald-950'
                          }`}
                        >
                          RISK: {action.risk_level}
                        </span>
                      </div>

                      {/* Status Tag */}
                      <div>
                        {action.status === 'executed_simulated' && (
                          <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-950/80 border border-emerald-700 px-2 py-1 rounded">
                            ✓ EXECUTED [SIMULATED]
                          </span>
                        )}
                        {action.status === 'rolled_back' && (
                          <span className="text-xs font-mono font-bold text-amber-400 bg-amber-950/80 border border-amber-700 px-2 py-1 rounded">
                            ↺ ROLLED BACK
                          </span>
                        )}
                        {action.status === 'rejected' && (
                          <span className="text-xs font-mono font-bold text-rose-400 bg-rose-950/80 border border-rose-700 px-2 py-1 rounded">
                            ✕ REJECTED
                          </span>
                        )}
                        {action.status === 'pending' && (
                          <span className="text-xs font-mono font-bold text-amber-400 bg-amber-950/80 border border-amber-700 px-2 py-1 rounded">
                            ⏳ PENDING APPROVAL
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Allowlist Warning Banner */}
                    {action.warning && (
                      <div className="my-2 p-2.5 rounded-lg bg-red-950/60 border border-red-800 text-xs text-red-300 flex items-center space-x-2">
                        <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
                        <span>{action.warning}</span>
                      </div>
                    )}

                    {/* Rationale */}
                    <p className="text-xs text-slate-300 my-1.5">{action.rationale}</p>

                    {/* Command Toggle */}
                    <div className="mt-2">
                      <button
                        onClick={() => toggleCommandView(action.id)}
                        className="text-[11px] font-mono text-blue-400 hover:text-blue-300 flex items-center space-x-1"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        <span>{isCmdExpanded ? 'Hide Rule Commands' : 'View Rule & Rollback Commands'}</span>
                      </button>

                      {isCmdExpanded && (
                        <div className="mt-2 space-y-2 bg-slate-900 p-3 rounded-lg border border-slate-800 text-xs font-mono">
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase font-semibold mb-1">
                              Simulated Enforcement Command:
                            </div>
                            <pre className="p-2 bg-black/60 rounded text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                              {action.command_text}
                            </pre>
                          </div>
                          {action.rollback_command && (
                            <div>
                              <div className="text-[10px] text-slate-400 uppercase font-semibold mb-1">
                                Rollback Command:
                              </div>
                              <pre className="p-2 bg-black/60 rounded text-amber-400 overflow-x-auto whitespace-pre-wrap">
                                {action.rollback_command}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Action Controls & Comment Box */}
                    {action.status === 'pending' && (
                      <div className="mt-3 pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
                        <input
                          type="text"
                          placeholder="Analyst comment (optional)..."
                          value={commentVal}
                          onChange={(e) => handleCommentChange(action.id, e.target.value)}
                          className="bg-slate-900 border border-slate-700 text-xs text-slate-200 px-3 py-1.5 rounded-lg flex-1 min-w-[200px] focus:outline-none focus:border-blue-500"
                        />
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => onApproveAction(action.id, commentVal)}
                            disabled={isLoading}
                            className="flex items-center space-x-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs px-3 py-1.5 rounded-lg shadow transition"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>Approve (Simulated)</span>
                          </button>
                          <button
                            onClick={() => onRejectAction(action.id, commentVal)}
                            disabled={isLoading}
                            className="flex items-center space-x-1.5 bg-rose-700 hover:bg-rose-600 text-white font-medium text-xs px-3 py-1.5 rounded-lg shadow transition"
                          >
                            <XCircle className="w-3.5 h-3.5" />
                            <span>Reject</span>
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Rollback button if executed */}
                    {action.status === 'executed_simulated' && action.reversible && (
                      <div className="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between">
                        <span className="text-[11px] text-slate-400 font-mono">
                          Executed at {action.executed_at ? new Date(action.executed_at).toLocaleTimeString() : 'now'} by {action.approved_by || 'analyst'}
                        </span>
                        <button
                          onClick={() => onRollbackAction(action.id)}
                          disabled={isLoading}
                          className="flex items-center space-x-1.5 bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs px-3 py-1.5 rounded-lg shadow transition"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          <span>Rollback Action</span>
                        </button>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}

        {/* 2. IOCs & Threat Intel Tab */}
        {activeTab === 'iocs' && (
          <div className="space-y-3">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border border-slate-800 rounded-lg overflow-hidden">
                <thead className="bg-slate-950 text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="p-3">Type</th>
                    <th className="p-3">Indicator Value</th>
                    <th className="p-3">Context</th>
                    <th className="p-3">Threat Reputation</th>
                    <th className="p-3">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 bg-slate-900/60 font-mono">
                  {incident.iocs.map((ioc) => {
                    const intel = incident.threat_intel_results.find((r) => r.ioc_id === ioc.id);
                    const score = intel ? intel.reputation_score : 0;
                    const isMal = intel ? intel.malicious : false;

                    return (
                      <tr key={ioc.id} className="hover:bg-slate-800/40">
                        <td className="p-3 uppercase text-blue-400 font-bold">{ioc.ioc_type}</td>
                        <td className="p-3 font-semibold text-slate-100 select-all">{ioc.value}</td>
                        <td className="p-3 text-slate-400">{ioc.context || '—'}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getReputationColor(score)}`}>
                            {score.toFixed(0)}/100 {isMal ? '🚨 MALICIOUS' : 'CLEAN'}
                          </span>
                        </td>
                        <td className="p-3 uppercase text-[10px] text-slate-400">{intel ? intel.source : 'N/A'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 3. Reasoning Timeline Tab */}
        {activeTab === 'timeline' && (
          <div className="space-y-4">
            {incident.agent_steps.map((step, idx) => (
              <div key={step.id} className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex space-x-3">
                <div className="flex flex-col items-center">
                  <div className="w-7 h-7 rounded-full bg-blue-600/20 border border-blue-500/50 flex items-center justify-center font-mono text-xs font-bold text-blue-400">
                    {idx + 1}
                  </div>
                  {idx < incident.agent_steps.length - 1 && <div className="w-0.5 bg-slate-800 flex-1 my-1"></div>}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-slate-100 uppercase">
                      {step.agent_name.replace('_', ' ')} AGENT
                    </span>
                    <span className="font-mono text-[11px] text-slate-500">{step.duration_ms}ms</span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1">{step.output_summary}</div>
                  {step.reasoning && (
                    <div className="mt-2 p-2 bg-slate-900 rounded text-xs text-slate-300 font-mono border border-slate-800/80">
                      <strong>Reasoning:</strong> {step.reasoning}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* 4. Raw Telemetry Tab */}
        {activeTab === 'raw' && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400">
                Source: {incident.event.source} • Format: {incident.event.event_type}
              </span>
            </div>
            <pre className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-emerald-400/90 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
              {incident.event.raw_content}
            </pre>
          </div>
        )}

        {/* 5. Audit Trail Tab */}
        {activeTab === 'audit' && (
          <div className="space-y-2 font-mono text-xs">
            {incident.audit_logs.map((log) => (
              <div key={log.id} className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg flex items-start justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-blue-400 font-bold uppercase">{log.actor}</span>
                    <span className="text-slate-500">→</span>
                    <span className="text-slate-200 font-semibold">{log.action}</span>
                  </div>
                  {log.details && (
                    <pre className="mt-1 text-[11px] text-slate-400 overflow-x-auto">
                      {JSON.stringify(log.details, null, 2)}
                    </pre>
                  )}
                </div>
                <span className="text-[10px] text-slate-500">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
