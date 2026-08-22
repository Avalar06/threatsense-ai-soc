/**
 * ThreatSense AI - Database Schema Definitions
 * 
 * Defines SQLite tables, indexes, and JSON serialization helpers for:
 * - alerts
 * - security_events
 * - incidents
 * - incident_reports
 * - ioc_records
 */

export const SCHEMA_SQL = `
-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'NEW',
  priority TEXT DEFAULT 'P2',
  host TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  destination_ip TEXT,
  username TEXT NOT NULL,
  detection_source TEXT DEFAULT 'RULE_BASED',
  rule_id TEXT,
  rule_name TEXT,
  detection_confidence INTEGER DEFAULT 100,
  ai_confidence INTEGER,
  description TEXT,
  evidence TEXT,
  related_event_ids TEXT,
  mitre_techniques TEXT,
  assigned_to TEXT,
  analyst_notes TEXT,
  gemini_analysis TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Security Events (Telemetry & Logs) Table
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  alert_id TEXT,
  timestamp TEXT NOT NULL,
  event_type TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  destination_ip TEXT NOT NULL,
  source_port INTEGER,
  destination_port INTEGER,
  hostname TEXT NOT NULL,
  username TEXT NOT NULL,
  process_name TEXT,
  command_line TEXT,
  action TEXT NOT NULL DEFAULT 'UNKNOWN',
  status TEXT NOT NULL DEFAULT 'SUCCESS',
  severity TEXT NOT NULL DEFAULT 'INFORMATIONAL',
  message TEXT NOT NULL,
  raw_text TEXT NOT NULL,
  metadata TEXT,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
);

-- Incidents (Case Management) Table
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'NEW',
  priority TEXT DEFAULT 'P2',
  lead_analyst TEXT,
  alert_ids TEXT,
  executive_summary TEXT,
  containment_actions TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT,
  closed_by TEXT,
  closure_summary TEXT
);

-- Incident Reports Table
CREATE TABLE IF NOT EXISTS incident_reports (
  id TEXT PRIMARY KEY,
  incident_id TEXT,
  report_title TEXT NOT NULL,
  author TEXT NOT NULL,
  status TEXT DEFAULT 'DRAFT',
  classification TEXT,
  report_data TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

-- IOC Records Table
CREATE TABLE IF NOT EXISTS ioc_records (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  defanged_value TEXT NOT NULL,
  threat_level TEXT NOT NULL DEFAULT 'UNKNOWN',
  context TEXT,
  source_event_id TEXT,
  confidence INTEGER DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT,
  tags TEXT
);

-- IOC Enrichments (Threat Intelligence Observations & External Enrichment) Table
CREATE TABLE IF NOT EXISTS ioc_enrichments (
  id TEXT PRIMARY KEY,
  ioc_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  reputation TEXT NOT NULL DEFAULT 'UNKNOWN',
  threat_level TEXT NOT NULL DEFAULT 'UNKNOWN',
  confidence INTEGER DEFAULT 0,
  classification TEXT,
  first_seen TEXT,
  last_seen TEXT,
  enriched_at TEXT NOT NULL,
  source TEXT,
  summary TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (ioc_id) REFERENCES ioc_records(id) ON DELETE CASCADE
);

-- Incident Response Actions (Containment & Remediation Tracking) Table
CREATE TABLE IF NOT EXISTS incident_response_actions (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'REQUESTED',
  requested_by TEXT NOT NULL,
  approved_by TEXT,
  requested_at TEXT NOT NULL,
  approved_at TEXT,
  executed_at TEXT,
  result TEXT,
  notes TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

-- Detection Strategies Table (MITRE ATT&CK Model)
CREATE TABLE IF NOT EXISTS detection_strategies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  technique_id TEXT NOT NULL,
  technique_name TEXT NOT NULL,
  tactic TEXT NOT NULL,
  attack_version TEXT NOT NULL,
  analytic_conditions TEXT NOT NULL,
  required_telemetry TEXT NOT NULL,
  supported_platforms TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence_model TEXT NOT NULL,
  evidence_requirements TEXT NOT NULL,
  is_active INTEGER DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Correlations Table (Persistent Correlation Matches with Explainable Risk)
CREATE TABLE IF NOT EXISTS correlations (
  id TEXT PRIMARY KEY,
  strategy_id TEXT NOT NULL,
  analytic_id TEXT NOT NULL,
  strategy_name TEXT,
  matched_event_ids TEXT NOT NULL,
  matched_alert_ids TEXT NOT NULL,
  ioc_ids TEXT,
  incident_id TEXT,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0,
  contributors TEXT NOT NULL,
  evidence TEXT NOT NULL,
  explanation TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

-- SOAR Playbooks Table
CREATE TABLE IF NOT EXISTS soar_playbooks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1.0.0',
  status TEXT NOT NULL DEFAULT 'ENABLED',
  trigger_type TEXT NOT NULL DEFAULT 'ALERT',
  trigger_conditions TEXT NOT NULL,
  policy TEXT NOT NULL,
  actions TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- SOAR Playbook Executions Table
CREATE TABLE IF NOT EXISTS soar_playbook_executions (
  id TEXT PRIMARY KEY,
  playbook_id TEXT NOT NULL,
  playbook_name TEXT NOT NULL,
  playbook_version TEXT NOT NULL,
  incident_id TEXT,
  alert_id TEXT,
  correlation_id TEXT,
  initiating_user TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  approved_by TEXT,
  approved_at TEXT,
  rejection_reason TEXT,
  current_step_index INTEGER DEFAULT 0,
  total_steps INTEGER DEFAULT 0,
  steps_state TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  FOREIGN KEY (playbook_id) REFERENCES soar_playbooks(id) ON DELETE CASCADE,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

-- SOAR Audit Logs Table
CREATE TABLE IF NOT EXISTS soar_audit_logs (
  id TEXT PRIMARY KEY,
  execution_id TEXT,
  incident_id TEXT,
  action_type TEXT NOT NULL,
  connector_id TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target TEXT NOT NULL,
  actor TEXT NOT NULL,
  event_type TEXT NOT NULL,
  details TEXT,
  timestamp TEXT NOT NULL
);

-- Indexes for Fast Querying
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);

CREATE INDEX IF NOT EXISTS idx_events_alert_id ON security_events(alert_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_hostname ON security_events(hostname);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON security_events(event_type);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);

CREATE INDEX IF NOT EXISTS idx_reports_incident_id ON incident_reports(incident_id);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON incident_reports(created_at);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON ioc_records(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON ioc_records(value);
CREATE INDEX IF NOT EXISTS idx_iocs_threat_level ON ioc_records(threat_level);

CREATE INDEX IF NOT EXISTS idx_enrichments_ioc_id ON ioc_enrichments(ioc_id);
CREATE INDEX IF NOT EXISTS idx_enrichments_provider ON ioc_enrichments(provider);
CREATE INDEX IF NOT EXISTS idx_enrichments_enriched_at ON ioc_enrichments(enriched_at);

CREATE INDEX IF NOT EXISTS idx_actions_incident_id ON incident_response_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_actions_status ON incident_response_actions(status);
CREATE INDEX IF NOT EXISTS idx_actions_action_type ON incident_response_actions(action_type);
CREATE INDEX IF NOT EXISTS idx_actions_requested_at ON incident_response_actions(requested_at);

CREATE INDEX IF NOT EXISTS idx_strategies_technique_id ON detection_strategies(technique_id);
CREATE INDEX IF NOT EXISTS idx_strategies_tactic ON detection_strategies(tactic);
CREATE INDEX IF NOT EXISTS idx_strategies_is_active ON detection_strategies(is_active);

CREATE INDEX IF NOT EXISTS idx_correlations_strategy_id ON correlations(strategy_id);
CREATE INDEX IF NOT EXISTS idx_correlations_severity ON correlations(severity);
CREATE INDEX IF NOT EXISTS idx_correlations_confidence ON correlations(confidence);
CREATE INDEX IF NOT EXISTS idx_correlations_created_at ON correlations(created_at);
CREATE INDEX IF NOT EXISTS idx_correlations_incident_id ON correlations(incident_id);

CREATE INDEX IF NOT EXISTS idx_playbooks_status ON soar_playbooks(status);
CREATE INDEX IF NOT EXISTS idx_playbooks_trigger_type ON soar_playbooks(trigger_type);

CREATE INDEX IF NOT EXISTS idx_executions_playbook_id ON soar_playbook_executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_executions_status ON soar_playbook_executions(status);
CREATE INDEX IF NOT EXISTS idx_executions_created_at ON soar_playbook_executions(created_at);
CREATE INDEX IF NOT EXISTS idx_executions_incident_id ON soar_playbook_executions(incident_id);

CREATE INDEX IF NOT EXISTS idx_soar_audit_execution_id ON soar_audit_logs(execution_id);
CREATE INDEX IF NOT EXISTS idx_soar_audit_incident_id ON soar_audit_logs(incident_id);
CREATE INDEX IF NOT EXISTS idx_soar_audit_timestamp ON soar_audit_logs(timestamp);
`;

export const REQUIRED_TABLES = [
  "alerts",
  "security_events",
  "incidents",
  "incident_reports",
  "ioc_records",
  "ioc_enrichments",
  "incident_response_actions",
  "detection_strategies",
  "correlations",
  "soar_playbooks",
  "soar_playbook_executions",
  "soar_audit_logs"
] as const;

export const REQUIRED_INDEXES = [
  "idx_alerts_severity",
  "idx_alerts_status",
  "idx_alerts_created_at",
  "idx_alerts_host",
  "idx_alerts_source_ip",
  "idx_events_alert_id",
  "idx_events_timestamp",
  "idx_events_hostname",
  "idx_events_source_ip",
  "idx_events_event_type",
  "idx_incidents_status",
  "idx_incidents_severity",
  "idx_incidents_created_at",
  "idx_reports_incident_id",
  "idx_reports_created_at",
  "idx_iocs_type",
  "idx_iocs_value",
  "idx_iocs_threat_level",
  "idx_enrichments_ioc_id",
  "idx_enrichments_provider",
  "idx_enrichments_enriched_at",
  "idx_actions_incident_id",
  "idx_actions_status",
  "idx_actions_action_type",
  "idx_actions_requested_at",
  "idx_strategies_technique_id",
  "idx_strategies_tactic",
  "idx_strategies_is_active",
  "idx_correlations_strategy_id",
  "idx_correlations_severity",
  "idx_correlations_confidence",
  "idx_correlations_created_at",
  "idx_correlations_incident_id",
  "idx_playbooks_status",
  "idx_playbooks_trigger_type",
  "idx_executions_playbook_id",
  "idx_executions_status",
  "idx_executions_created_at",
  "idx_executions_incident_id",
  "idx_soar_audit_execution_id",
  "idx_soar_audit_incident_id",
  "idx_soar_audit_timestamp"
] as const;

/**
 * Safely parse JSON strings from SQLite storage, returning fallback if invalid.
 */
export function safeJsonParse<T>(jsonStr: string | null | undefined, fallback: T): T {
  if (!jsonStr) return fallback;
  try {
    return JSON.parse(jsonStr) as T;
  } catch {
    return fallback;
  }
}

/**
 * Safely stringify objects for SQLite column storage.
 */
export function safeJsonStringify(val: unknown): string {
  if (val === undefined || val === null) return "null";
  try {
    return JSON.stringify(val);
  } catch {
    return "null";
  }
}
