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
  closed_at TEXT
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
`;

export const REQUIRED_TABLES = [
  "alerts",
  "security_events",
  "incidents",
  "incident_reports",
  "ioc_records"
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
  "idx_iocs_threat_level"
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
