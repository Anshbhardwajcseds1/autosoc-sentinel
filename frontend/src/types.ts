export type Severity = 'Low' | 'Medium' | 'High' | 'Critical';
export type IncidentStatus = 'analyzing' | 'awaiting_review' | 'resolved' | 'escalated';
export type ActionType = 'block_ip' | 'block_domain' | 'quarantine_email' | 'lock_account' | 'force_password_reset' | 'revoke_sessions';
export type ActionStatus = 'pending' | 'approved' | 'rejected' | 'executed_simulated' | 'rolled_back';
export type RiskLevel = 'low' | 'medium' | 'high';

export interface IOC {
  id: string;
  ioc_type: string;
  value: string;
  context?: string;
}

export interface ThreatIntelResult {
  id: string;
  ioc_id: string;
  source: string;
  reputation_score: number;
  malicious: boolean;
  raw_response?: any;
  cached: boolean;
  queried_at: string;
}

export interface ContainmentAction {
  id: string;
  incident_id: string;
  action_type: ActionType;
  target: string;
  rationale?: string;
  risk_level: RiskLevel;
  reversible: boolean;
  command_text?: string;
  rollback_command?: string;
  status: ActionStatus;
  analyst_comment?: string;
  approved_by?: string;
  approved_at?: string;
  executed_at?: string;
  is_recommended: boolean;
  warning?: string;
}

export interface AgentStep {
  id: string;
  agent_name: string;
  input_summary?: string;
  output_summary?: string;
  reasoning?: string;
  duration_ms?: number;
  status: 'success' | 'error';
  error_message?: string;
  timestamp: string;
}

export interface AuditLog {
  id: string;
  incident_id?: string;
  actor: string;
  action: string;
  details?: any;
  timestamp: string;
}

export interface EventData {
  id: string;
  event_type: string;
  raw_content: string;
  source: string;
  created_at: string;
}

export interface IncidentSummary {
  id: string;
  event_id: string;
  status: IncidentStatus;
  severity?: Severity;
  summary?: string;
  incident_type?: string;
  confidence?: number;
  created_at: string;
  updated_at: string;
  ioc_count: number;
  action_count: number;
  pending_action_count: number;
}

export interface IncidentDetail extends IncidentSummary {
  event: EventData;
  iocs: IOC[];
  threat_intel_results: ThreatIntelResult[];
  actions: ContainmentAction[];
  agent_steps: AgentStep[];
  audit_logs: AuditLog[];
}

export interface DashboardStats {
  incidents_today: number;
  total_incidents: number;
  open_incidents: number;
  critical_incidents: number;
  high_incidents: number;
  medium_incidents: number;
  low_incidents: number;
  total_actions: number;
  approved_actions: number;
  rejected_actions: number;
  pending_actions: number;
  approval_rate: number;
  mean_time_to_respond_seconds?: number | null;
}
