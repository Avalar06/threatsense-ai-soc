/**
 * ThreatSense AI - SQLite Database Access & Persistence Engine
 * 
 * Provides server-side SQLite persistence using Node.js built-in DatabaseSync
 * with parameterized queries, schema verification, and automated directory creation.
 */

import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { SCHEMA_SQL, safeJsonParse, safeJsonStringify } from "./schema.js";
import { seedDefaultsIfEmpty } from "./seedDefaults.js";
import type {
  Alert,
  SecurityEvent,
  IncidentReport,
  IOC,
  MitreTechnique,
  GeminiInvestigationResult,
  IncidentResponseAction,
  DetectionStrategy,
  CorrelationRecord,
  CorrelationEvidence,
  RiskContributor,
  SoarPlaybook,
  SoarPlaybookExecution,
  PlaybookStepState,
  SoarAuditLog,
  SoarConnectorInfo
} from "../../src/types/soc.js";

export interface CorrelationFilters {
  strategyId?: string;
  severity?: string;
  confidence?: string;
  incidentId?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface StrategyFilters {
  tactic?: string;
  techniqueId?: string;
  isActive?: boolean;
  search?: string;
}

export interface ExecutionFilters {
  playbookId?: string;
  status?: string;
  incidentId?: string;
  alertId?: string;
  correlationId?: string;
  limit?: number;
  offset?: number;
}

export interface AuditLogFilters {
  executionId?: string;
  incidentId?: string;
  actionType?: string;
  connectorId?: string;
  limit?: number;
  offset?: number;
}

export interface IncidentResponseActionRecord {
  id: string;
  incidentId: string;
  actionType: string;
  targetType: string;
  target: string;
  status: string;
  requestedBy: string;
  approvedBy?: string;
  requestedAt: string;
  approvedAt?: string;
  executedAt?: string;
  result?: string;
  notes?: string;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
}

export interface IocEnrichmentRecord {
  id: string;
  iocId: string;
  provider: string;
  reputation: "UNKNOWN" | "MALICIOUS" | "SUSPICIOUS" | "BENIGN";
  threatLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  confidence: number;
  classification?: string;
  firstSeen?: string;
  lastSeen?: string;
  enrichedAt: string;
  source?: string;
  summary: string;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentRecord {
  id: string;
  title: string;
  severity: string;
  status: string;
  priority?: string;
  leadAnalyst?: string;
  alertIds: string[];
  executiveSummary?: string;
  containmentActions: string[];
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
  closedBy?: string;
  closureSummary?: string;
}

export const DEFAULT_DB_PATH =
  process.env.THREATSENSE_DB_PATH || path.join(process.cwd(), "data", "threatsense.db");

let activeDbInstance: DatabaseSync | null = null;

export interface AlertFilters {
  severity?: string;
  status?: string;
  priority?: string;
  search?: string;
  host?: string;
  sourceIp?: string;
  limit?: number;
  offset?: number;
}

export interface EventFilters {
  alertId?: string;
  hostname?: string;
  sourceIp?: string;
  eventType?: string;
  startTime?: string;
  endTime?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface IncidentFilters {
  status?: string;
  severity?: string;
  priority?: string;
  leadAnalyst?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface IocFilters {
  type?: string;
  threatLevel?: string;
  search?: string;
  alertId?: string;
  incidentId?: string;
  limit?: number;
  offset?: number;
}

export interface ReportFilters {
  incidentId?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface DashboardStats {
  totalAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  mediumAlerts: number;
  lowAlerts: number;
  infoAlerts: number;
  newAlerts: number;
  inProgressAlerts: number;
  resolvedAlerts: number;
  closedAlerts: number;
  activeHosts: number;
  averageRiskScore: number;
  alertsBySeverity: Record<string, number>;
  alertsByStatus: Record<string, number>;
}

/**
 * Initializes and returns a SQLite database instance.
 * Automatically creates parent directories and executes idempotent schema migrations.
 */
export function initDatabase(dbPath: string = DEFAULT_DB_PATH): DatabaseSync {
  if (dbPath !== ":memory:") {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(dbPath);

  // Enable foreign keys and WAL mode (WAL for file-based dbs)
  db.exec("PRAGMA foreign_keys = ON;");
  if (dbPath !== ":memory:") {
    db.exec("PRAGMA journal_mode = WAL;");
  }

  // Execute schema creation (CREATE TABLE IF NOT EXISTS & CREATE INDEX IF NOT EXISTS)
  db.exec(SCHEMA_SQL);

  // Seed default detection strategies and playbooks if empty
  seedDefaultsIfEmpty(db);

  return db;
}

/**
 * Returns the singleton active database instance, initializing it if not already open.
 */
export function getDatabase(dbPath: string = DEFAULT_DB_PATH): DatabaseSync {
  if (!activeDbInstance) {
    activeDbInstance = initDatabase(dbPath);
  }
  return activeDbInstance;
}

/**
 * Closes the active database connection.
 */
export function closeDatabase(db?: DatabaseSync): void {
  const target = db || activeDbInstance;
  if (target) {
    try {
      target.close();
    } catch {
      // Ignore if already closed
    }
    if (target === activeDbInstance) {
      activeDbInstance = null;
    }
  }
}

// ==========================================
// TYPED PARAMETERIZED REPOSITORY FUNCTIONS
// ==========================================

export class SocDatabase {
  private db: DatabaseSync;

  constructor(dbOrPath?: DatabaseSync | string) {
    if (typeof dbOrPath === "string") {
      this.db = initDatabase(dbOrPath);
    } else if (dbOrPath) {
      this.db = dbOrPath;
    } else {
      this.db = getDatabase();
    }
  }

  get rawDb(): DatabaseSync {
    return this.db;
  }

  // ------------------------------------------
  // ALERTS REPOSITORY
  // ------------------------------------------

  insertAlert(alert: Alert): void {
    const stmt = this.db.prepare(`
      INSERT INTO alerts (
        id, title, severity, risk_score, status, priority, host, source_ip,
        destination_ip, username, detection_source, rule_id, rule_name,
        detection_confidence, ai_confidence, description, evidence,
        related_event_ids, mitre_techniques, assigned_to, analyst_notes,
        gemini_analysis, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?
      )
    `);

    const now = new Date().toISOString();
    stmt.run(
      alert.id,
      alert.title,
      alert.severity,
      alert.riskScore ?? 0,
      alert.status ?? "NEW",
      "P2", // default priority
      alert.host,
      alert.sourceIp,
      alert.destinationIp ?? null,
      alert.username,
      alert.detectionSource ?? "RULE_BASED",
      alert.ruleId ?? null,
      alert.ruleName ?? null,
      alert.detectionConfidence ?? 100,
      alert.aiConfidence ?? null,
      alert.description ?? "",
      safeJsonStringify(alert.evidence ?? []),
      safeJsonStringify(alert.relatedEventIds ?? []),
      safeJsonStringify(alert.mitreTechniques ?? []),
      alert.assignedTo ?? null,
      alert.notes ?? null,
      safeJsonStringify(alert.geminiAnalysis ?? null),
      alert.timestamp || now,
      alert.updatedAt || now
    );
  }

  getAlertById(id: string): Alert | null {
    const stmt = this.db.prepare("SELECT * FROM alerts WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToAlert(row);
  }

  existsAlert(id: string): boolean {
    const stmt = this.db.prepare("SELECT id FROM alerts WHERE id = ?");
    return Boolean(stmt.get(id));
  }

  getAllAlerts(): Alert[] {
    const stmt = this.db.prepare("SELECT * FROM alerts ORDER BY created_at DESC");
    const rows = stmt.all() as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToAlert(r));
  }

  listAlerts(filters: AlertFilters = {}): {
    alerts: Alert[];
    total: number;
    limit: number;
    offset: number;
  } {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.severity) {
      conditions.push("UPPER(severity) = UPPER(?)");
      params.push(filters.severity);
    }
    if (filters.status) {
      conditions.push("UPPER(status) = UPPER(?)");
      params.push(filters.status);
    }
    if (filters.priority) {
      conditions.push("UPPER(priority) = UPPER(?)");
      params.push(filters.priority);
    }
    if (filters.host) {
      conditions.push("host LIKE ?");
      params.push(`%${filters.host}%`);
    }
    if (filters.sourceIp) {
      conditions.push("source_ip = ?");
      params.push(filters.sourceIp);
    }
    if (filters.search && filters.search.trim()) {
      const term = `%${filters.search.trim()}%`;
      conditions.push(
        "(title LIKE ? OR host LIKE ? OR source_ip LIKE ? OR username LIKE ? OR id LIKE ? OR rule_name LIKE ? OR description LIKE ?)"
      );
      params.push(term, term, term, term, term, term, term);
    }

    const whereClause = conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : "";

    const countStmt = this.db.prepare(`SELECT COUNT(*) as count FROM alerts${whereClause}`);
    const countRow = countStmt.get(...params) as { count: number } | undefined;
    const total = Number(countRow?.count || 0);

    const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 200);
    const offset = Math.max(Number(filters.offset) || 0, 0);

    const queryStmt = this.db.prepare(
      `SELECT * FROM alerts${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    );
    const rows = queryStmt.all(...params, limit, offset) as Record<string, unknown>[];

    return {
      alerts: rows.map((r) => this.mapRowToAlert(r)),
      total,
      limit,
      offset,
    };
  }

  updateAlert(id: string, updates: Partial<Alert>): boolean {
    const current = this.getAlertById(id);
    if (!current) return false;

    const merged = { ...current, ...updates, updatedAt: new Date().toISOString() };
    const stmt = this.db.prepare(`
      UPDATE alerts SET
        title = ?,
        severity = ?,
        risk_score = ?,
        status = ?,
        host = ?,
        source_ip = ?,
        destination_ip = ?,
        username = ?,
        detection_source = ?,
        rule_id = ?,
        rule_name = ?,
        detection_confidence = ?,
        ai_confidence = ?,
        description = ?,
        evidence = ?,
        related_event_ids = ?,
        mitre_techniques = ?,
        assigned_to = ?,
        analyst_notes = ?,
        gemini_analysis = ?,
        updated_at = ?
      WHERE id = ?
    `);

    stmt.run(
      merged.title,
      merged.severity,
      merged.riskScore,
      merged.status,
      merged.host,
      merged.sourceIp,
      merged.destinationIp ?? null,
      merged.username,
      merged.detectionSource,
      merged.ruleId ?? null,
      merged.ruleName ?? null,
      merged.detectionConfidence,
      merged.aiConfidence ?? null,
      merged.description,
      safeJsonStringify(merged.evidence),
      safeJsonStringify(merged.relatedEventIds),
      safeJsonStringify(merged.mitreTechniques),
      merged.assignedTo ?? null,
      merged.notes ?? null,
      safeJsonStringify(merged.geminiAnalysis ?? null),
      merged.updatedAt,
      id
    );
    return true;
  }

  deleteAlert(id: string): boolean {
    const stmt = this.db.prepare("DELETE FROM alerts WHERE id = ?");
    stmt.run(id);
    return true;
  }

  // ------------------------------------------
  // SECURITY EVENTS REPOSITORY
  // ------------------------------------------

  insertEvent(event: SecurityEvent, alertId?: string): void {
    const stmt = this.db.prepare(`
      INSERT INTO security_events (
        id, alert_id, timestamp, event_type, source_ip, destination_ip,
        source_port, destination_port, hostname, username, process_name,
        command_line, action, status, severity, message, raw_text, metadata
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?
      )
    `);

    stmt.run(
      event.id,
      alertId ?? null,
      event.timestamp,
      event.event_type,
      event.source_ip,
      event.destination_ip,
      event.source_port ?? null,
      event.destination_port ?? null,
      event.hostname,
      event.username,
      event.process ?? null,
      (event.metadata?.command_line as string) ?? null,
      event.action ?? "UNKNOWN",
      event.status ?? "SUCCESS",
      event.severity ?? "INFORMATIONAL",
      event.message,
      event.raw,
      safeJsonStringify(event.metadata ?? null)
    );
  }

  insertEventsBatch(events: SecurityEvent[], alertId?: string): void {
    for (const ev of events) {
      this.insertEvent(ev, alertId);
    }
  }

  updateEventAlertId(eventId: string, alertId: string): void {
    const stmt = this.db.prepare("UPDATE security_events SET alert_id = ? WHERE id = ?");
    stmt.run(alertId, eventId);
  }

  getEventsByAlertId(alertId: string): SecurityEvent[] {
    const stmt = this.db.prepare("SELECT * FROM security_events WHERE alert_id = ? ORDER BY timestamp ASC");
    const rows = stmt.all(alertId) as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToSecurityEvent(r));
  }

  getAllEvents(limit = 1000): SecurityEvent[] {
    const stmt = this.db.prepare("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?");
    const rows = stmt.all(limit) as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToSecurityEvent(r));
  }

  listSecurityEvents(filters: EventFilters = {}): {
    events: SecurityEvent[];
    total: number;
    limit: number;
    offset: number;
  } {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.alertId) {
      conditions.push("alert_id = ?");
      params.push(filters.alertId);
    }
    if (filters.hostname) {
      conditions.push("hostname LIKE ?");
      params.push(`%${filters.hostname}%`);
    }
    if (filters.sourceIp) {
      conditions.push("source_ip = ?");
      params.push(filters.sourceIp);
    }
    if (filters.eventType) {
      conditions.push("UPPER(event_type) = UPPER(?)");
      params.push(filters.eventType);
    }
    if (filters.startTime) {
      conditions.push("timestamp >= ?");
      params.push(filters.startTime);
    }
    if (filters.endTime) {
      conditions.push("timestamp <= ?");
      params.push(filters.endTime);
    }
    if (filters.search && filters.search.trim()) {
      const term = `%${filters.search.trim()}%`;
      conditions.push(
        "(message LIKE ? OR raw_text LIKE ? OR hostname LIKE ? OR username LIKE ? OR process_name LIKE ?)"
      );
      params.push(term, term, term, term, term);
    }

    const whereClause = conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : "";

    const countStmt = this.db.prepare(`SELECT COUNT(*) as count FROM security_events${whereClause}`);
    const countRow = countStmt.get(...params) as { count: number } | undefined;
    const total = Number(countRow?.count || 0);

    const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 200);
    const offset = Math.max(Number(filters.offset) || 0, 0);

    const queryStmt = this.db.prepare(
      `SELECT * FROM security_events${whereClause} ORDER BY timestamp DESC LIMIT ? OFFSET ?`
    );
    const rows = queryStmt.all(...params, limit, offset) as Record<string, unknown>[];

    return {
      events: rows.map((r) => this.mapRowToSecurityEvent(r)),
      total,
      limit,
      offset,
    };
  }

  // ------------------------------------------
  // INCIDENTS REPOSITORY
  // ------------------------------------------

  insertIncident(incident: IncidentRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO incidents (
        id, title, severity, status, priority, lead_analyst,
        alert_ids, executive_summary, containment_actions,
        created_at, updated_at, closed_at, closed_by, closure_summary
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?, ?
      )
    `);

    stmt.run(
      incident.id,
      incident.title,
      incident.severity,
      incident.status,
      incident.priority ?? "P2",
      incident.leadAnalyst ?? null,
      safeJsonStringify(incident.alertIds ?? []),
      incident.executiveSummary ?? null,
      safeJsonStringify(incident.containmentActions ?? []),
      incident.createdAt,
      incident.updatedAt,
      incident.closedAt ?? null,
      incident.closedBy ?? null,
      incident.closureSummary ?? null
    );
  }

  getIncidentById(id: string): IncidentRecord | null {
    const stmt = this.db.prepare("SELECT * FROM incidents WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToIncident(row);
  }

  existsIncident(id: string): boolean {
    const stmt = this.db.prepare("SELECT id FROM incidents WHERE id = ?");
    return Boolean(stmt.get(id));
  }

  getAllIncidents(): IncidentRecord[] {
    const stmt = this.db.prepare("SELECT * FROM incidents ORDER BY created_at DESC");
    const rows = stmt.all() as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToIncident(r));
  }

  listIncidents(filters: IncidentFilters = {}): {
    incidents: IncidentRecord[];
    total: number;
    limit: number;
    offset: number;
  } {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.status) {
      conditions.push("UPPER(status) = UPPER(?)");
      params.push(filters.status);
    }
    if (filters.severity) {
      conditions.push("UPPER(severity) = UPPER(?)");
      params.push(filters.severity);
    }
    if (filters.priority) {
      conditions.push("UPPER(priority) = UPPER(?)");
      params.push(filters.priority);
    }
    if (filters.leadAnalyst && filters.leadAnalyst.trim()) {
      conditions.push("lead_analyst = ?");
      params.push(filters.leadAnalyst.trim());
    }
    if (filters.search && filters.search.trim()) {
      const term = `%${filters.search.trim()}%`;
      conditions.push(
        "(title LIKE ? OR lead_analyst LIKE ? OR executive_summary LIKE ? OR id LIKE ?)"
      );
      params.push(term, term, term, term);
    }

    const whereClause = conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : "";

    const countStmt = this.db.prepare(`SELECT COUNT(*) as count FROM incidents${whereClause}`);
    const countRow = countStmt.get(...params) as { count: number } | undefined;
    const total = Number(countRow?.count || 0);

    const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 200);
    const offset = Math.max(Number(filters.offset) || 0, 0);

    const queryStmt = this.db.prepare(
      `SELECT * FROM incidents${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    );
    const rows = queryStmt.all(...params, limit, offset) as Record<string, unknown>[];

    return {
      incidents: rows.map((r) => this.mapRowToIncident(r)),
      total,
      limit,
      offset,
    };
  }

  updateIncident(id: string, updates: Partial<IncidentRecord>): boolean {
    const current = this.getIncidentById(id);
    if (!current) return false;
    const merged = { ...current, ...updates, updatedAt: new Date().toISOString() };

    const stmt = this.db.prepare(`
      UPDATE incidents SET
        title = ?,
        severity = ?,
        status = ?,
        priority = ?,
        lead_analyst = ?,
        alert_ids = ?,
        executive_summary = ?,
        containment_actions = ?,
        updated_at = ?,
        closed_at = ?,
        closed_by = ?,
        closure_summary = ?
      WHERE id = ?
    `);

    stmt.run(
      merged.title,
      merged.severity,
      merged.status,
      merged.priority ?? "P2",
      merged.leadAnalyst ?? null,
      safeJsonStringify(merged.alertIds ?? []),
      merged.executiveSummary ?? null,
      safeJsonStringify(merged.containmentActions ?? []),
      merged.updatedAt,
      merged.closedAt ?? null,
      merged.closedBy ?? null,
      merged.closureSummary ?? null,
      id
    );
    return true;
  }

  // ------------------------------------------
  // INCIDENT RESPONSE ACTIONS REPOSITORY
  // ------------------------------------------

  insertIncidentAction(action: IncidentResponseActionRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO incident_response_actions (
        id, incident_id, action_type, target_type, target, status,
        requested_by, approved_by, requested_at, approved_at, executed_at,
        result, notes, metadata, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?
      )
    `);

    stmt.run(
      action.id,
      action.incidentId,
      action.actionType,
      action.targetType,
      action.target,
      action.status,
      action.requestedBy,
      action.approvedBy ?? null,
      action.requestedAt,
      action.approvedAt ?? null,
      action.executedAt ?? null,
      action.result ?? null,
      action.notes ?? null,
      safeJsonStringify(action.metadata ?? null),
      action.createdAt,
      action.updatedAt
    );
  }

  getIncidentActionById(id: string): IncidentResponseActionRecord | null {
    const stmt = this.db.prepare("SELECT * FROM incident_response_actions WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToIncidentAction(row);
  }

  existsIncidentAction(id: string): boolean {
    const stmt = this.db.prepare("SELECT id FROM incident_response_actions WHERE id = ?");
    return Boolean(stmt.get(id));
  }

  getIncidentActionsByIncidentId(incidentId: string): IncidentResponseActionRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM incident_response_actions 
      WHERE incident_id = ? 
      ORDER BY requested_at DESC, created_at DESC
    `);
    const rows = stmt.all(incidentId) as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToIncidentAction(r));
  }

  updateIncidentAction(id: string, updates: Partial<IncidentResponseActionRecord>): boolean {
    const current = this.getIncidentActionById(id);
    if (!current) return false;
    const merged = { ...current, ...updates, updatedAt: new Date().toISOString() };

    const stmt = this.db.prepare(`
      UPDATE incident_response_actions SET
        status = ?,
        approved_by = ?,
        approved_at = ?,
        executed_at = ?,
        result = ?,
        notes = ?,
        metadata = ?,
        updated_at = ?
      WHERE id = ?
    `);

    stmt.run(
      merged.status,
      merged.approvedBy ?? null,
      merged.approvedAt ?? null,
      merged.executedAt ?? null,
      merged.result ?? null,
      merged.notes ?? null,
      safeJsonStringify(merged.metadata ?? null),
      merged.updatedAt,
      id
    );
    return true;
  }

  // ------------------------------------------
  // INCIDENT REPORTS REPOSITORY
  // ------------------------------------------

  insertReport(report: IncidentReport): void {
    let validIncidentId: string | null = null;
    if (report.incidentId) {
      const checkStmt = this.db.prepare("SELECT id FROM incidents WHERE id = ?");
      const found = checkStmt.get(report.incidentId);
      if (found) {
        validIncidentId = report.incidentId;
      }
    }

    const stmt = this.db.prepare(`
      INSERT INTO incident_reports (
        id, incident_id, report_title, author, status,
        classification, report_data, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?
      )
    `);

    const now = new Date().toISOString();
    stmt.run(
      report.id,
      validIncidentId,
      report.reportTitle,
      report.author,
      report.status ?? "DRAFT",
      report.classification ?? null,
      safeJsonStringify(report),
      report.createdAt || report.generatedAt || now,
      now
    );
  }

  getReportById(id: string): IncidentReport | null {
    const stmt = this.db.prepare("SELECT * FROM incident_reports WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return safeJsonParse<IncidentReport | null>(row.report_data as string, null);
  }

  existsReport(id: string): boolean {
    const stmt = this.db.prepare("SELECT id FROM incident_reports WHERE id = ?");
    return Boolean(stmt.get(id));
  }

  getAllReports(): IncidentReport[] {
    const stmt = this.db.prepare("SELECT * FROM incident_reports ORDER BY created_at DESC");
    const rows = stmt.all() as Record<string, unknown>[];
    return rows
      .map((r) => safeJsonParse<IncidentReport | null>(r.report_data as string, null))
      .filter((r): r is IncidentReport => r !== null);
  }

  listReports(filters: ReportFilters = {}): {
    reports: IncidentReport[];
    total: number;
    limit: number;
    offset: number;
  } {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.incidentId) {
      conditions.push("incident_id = ?");
      params.push(filters.incidentId);
    }
    if (filters.search && filters.search.trim()) {
      const term = `%${filters.search.trim()}%`;
      conditions.push("(report_title LIKE ? OR author LIKE ? OR report_data LIKE ?)");
      params.push(term, term, term);
    }

    const whereClause = conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : "";

    const countStmt = this.db.prepare(`SELECT COUNT(*) as count FROM incident_reports${whereClause}`);
    const countRow = countStmt.get(...params) as { count: number } | undefined;
    const total = Number(countRow?.count || 0);

    const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 200);
    const offset = Math.max(Number(filters.offset) || 0, 0);

    const queryStmt = this.db.prepare(
      `SELECT * FROM incident_reports${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    );
    const rows = queryStmt.all(...params, limit, offset) as Record<string, unknown>[];

    return {
      reports: rows
        .map((r) => safeJsonParse<IncidentReport | null>(r.report_data as string, null))
        .filter((r): r is IncidentReport => r !== null),
      total,
      limit,
      offset,
    };
  }

  // ------------------------------------------
  // DASHBOARD METRICS REPOSITORY
  // ------------------------------------------

  getDashboardStats(): DashboardStats {
    const totalRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts").get() as { c: number } | undefined;
    const totalAlerts = Number(totalRow?.c || 0);

    const critRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(severity) = 'CRITICAL'").get() as { c: number } | undefined;
    const criticalAlerts = Number(critRow?.c || 0);

    const highRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(severity) = 'HIGH'").get() as { c: number } | undefined;
    const highAlerts = Number(highRow?.c || 0);

    const medRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(severity) = 'MEDIUM'").get() as { c: number } | undefined;
    const mediumAlerts = Number(medRow?.c || 0);

    const lowRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(severity) = 'LOW'").get() as { c: number } | undefined;
    const lowAlerts = Number(lowRow?.c || 0);

    const infoRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(severity) IN ('INFO', 'INFORMATIONAL')").get() as { c: number } | undefined;
    const infoAlerts = Number(infoRow?.c || 0);

    const newRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(status) = 'NEW'").get() as { c: number } | undefined;
    const newAlerts = Number(newRow?.c || 0);

    const inProgRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(status) IN ('IN_PROGRESS', 'INVESTIGATING', 'ESCALATED')").get() as { c: number } | undefined;
    const inProgressAlerts = Number(inProgRow?.c || 0);

    const resRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(status) = 'RESOLVED'").get() as { c: number } | undefined;
    const resolvedAlerts = Number(resRow?.c || 0);

    const closedRow = this.db.prepare("SELECT COUNT(*) as c FROM alerts WHERE UPPER(status) = 'CLOSED'").get() as { c: number } | undefined;
    const closedAlerts = Number(closedRow?.c || 0);

    const hostRow = this.db.prepare("SELECT COUNT(DISTINCT host) as c FROM alerts").get() as { c: number } | undefined;
    const activeHosts = Number(hostRow?.c || 0);

    const avgRiskRow = this.db.prepare("SELECT AVG(risk_score) as avg FROM alerts").get() as { avg: number | null } | undefined;
    const averageRiskScore = avgRiskRow?.avg ? Math.round(Number(avgRiskRow.avg)) : 0;

    const alertsBySeverity: Record<string, number> = {
      CRITICAL: criticalAlerts,
      HIGH: highAlerts,
      MEDIUM: mediumAlerts,
      LOW: lowAlerts,
      INFO: infoAlerts,
    };

    const alertsByStatus: Record<string, number> = {
      NEW: newAlerts,
      IN_PROGRESS: inProgressAlerts,
      RESOLVED: resolvedAlerts,
      CLOSED: closedAlerts,
    };

    return {
      totalAlerts,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      lowAlerts,
      infoAlerts,
      newAlerts,
      inProgressAlerts,
      resolvedAlerts,
      closedAlerts,
      activeHosts,
      averageRiskScore,
      alertsBySeverity,
      alertsByStatus,
    };
  }

  // ------------------------------------------
  // IOC RECORDS & ENRICHMENTS REPOSITORY
  // ------------------------------------------

  insertIoc(ioc: IOC): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO ioc_records (
        id, type, value, defanged_value, threat_level,
        context, source_event_id, confidence, first_seen, last_seen, tags
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?
      )
    `);

    const now = new Date().toISOString();
    stmt.run(
      ioc.id,
      ioc.type,
      ioc.value,
      ioc.defangedValue,
      ioc.riskLevel,
      ioc.context ?? "",
      ioc.sourceEventId ?? null,
      ioc.confidence ?? 0,
      ioc.firstSeen || now,
      ioc.lastSeen || now,
      safeJsonStringify(ioc.tags ?? [])
    );
  }

  getIocById(id: string): IOC | null {
    const stmt = this.db.prepare("SELECT * FROM ioc_records WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToIoc(row);
  }

  getIocByValue(value: string): IOC | null {
    const stmt = this.db.prepare("SELECT * FROM ioc_records WHERE value = ?");
    const row = stmt.get(value) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToIoc(row);
  }

  getAllIocs(): IOC[] {
    const stmt = this.db.prepare("SELECT * FROM ioc_records ORDER BY first_seen DESC");
    const rows = stmt.all() as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToIoc(r));
  }

  listIocs(filters: IocFilters = {}): {
    iocs: (IOC & { latestEnrichment?: IocEnrichmentRecord | null; relatedAlertCount?: number; relatedIncidentCount?: number })[];
    total: number;
    limit: number;
    offset: number;
  } {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.type) {
      conditions.push("UPPER(type) = UPPER(?)");
      params.push(filters.type);
    }
    if (filters.threatLevel) {
      conditions.push("UPPER(threat_level) = UPPER(?)");
      params.push(filters.threatLevel);
    }
    if (filters.search && filters.search.trim()) {
      const term = `%${filters.search.trim()}%`;
      conditions.push("(value LIKE ? OR defanged_value LIKE ? OR context LIKE ? OR id LIKE ?)");
      params.push(term, term, term, term);
    }

    const whereClause = conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : "";

    const countStmt = this.db.prepare(`SELECT COUNT(*) as count FROM ioc_records${whereClause}`);
    const countRow = countStmt.get(...params) as { count: number } | undefined;
    const total = Number(countRow?.count || 0);

    const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 200);
    const offset = Math.max(Number(filters.offset) || 0, 0);

    const queryStmt = this.db.prepare(
      `SELECT * FROM ioc_records${whereClause} ORDER BY first_seen DESC LIMIT ? OFFSET ?`
    );
    const rows = queryStmt.all(...params, limit, offset) as Record<string, unknown>[];

    const iocs = rows.map((r) => {
      const ioc = this.mapRowToIoc(r);
      const latestEnrichment = this.getLatestEnrichmentByIocId(ioc.id);
      
      // Calculate related alert and incident counts
      const alertMatches = this.db.prepare(`
        SELECT COUNT(*) as c FROM alerts 
        WHERE source_ip = ? OR destination_ip = ? OR host = ? OR evidence LIKE ?
      `).get(ioc.value, ioc.value, ioc.value, `%${ioc.value}%`) as { c: number } | undefined;

      return {
        ...ioc,
        latestEnrichment,
        relatedAlertCount: Number(alertMatches?.c || 0),
        relatedIncidentCount: 0,
      };
    });

    return {
      iocs,
      total,
      limit,
      offset,
    };
  }

  insertIocEnrichment(enrichment: IocEnrichmentRecord): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO ioc_enrichments (
        id, ioc_id, provider, reputation, threat_level,
        confidence, classification, first_seen, last_seen,
        enriched_at, source, summary, metadata, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?
      )
    `);

    stmt.run(
      enrichment.id,
      enrichment.iocId,
      enrichment.provider,
      enrichment.reputation,
      enrichment.threatLevel,
      enrichment.confidence,
      enrichment.classification ?? null,
      enrichment.firstSeen ?? null,
      enrichment.lastSeen ?? null,
      enrichment.enrichedAt,
      enrichment.source ?? null,
      enrichment.summary,
      safeJsonStringify(enrichment.metadata ?? null),
      enrichment.createdAt,
      enrichment.updatedAt
    );
  }

  getEnrichmentsByIocId(iocId: string): IocEnrichmentRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM ioc_enrichments 
      WHERE ioc_id = ? 
      ORDER BY enriched_at DESC, created_at DESC
    `);
    const rows = stmt.all(iocId) as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToIocEnrichment(r));
  }

  getLatestEnrichmentByIocId(iocId: string, provider?: string): IocEnrichmentRecord | null {
    if (provider) {
      const stmt = this.db.prepare(`
        SELECT * FROM ioc_enrichments 
        WHERE ioc_id = ? AND provider = ? 
        ORDER BY enriched_at DESC LIMIT 1
      `);
      const row = stmt.get(iocId, provider) as Record<string, unknown> | undefined;
      if (!row) return null;
      return this.mapRowToIocEnrichment(row);
    }
    const stmt = this.db.prepare(`
      SELECT * FROM ioc_enrichments 
      WHERE ioc_id = ? 
      ORDER BY enriched_at DESC LIMIT 1
    `);
    const row = stmt.get(iocId) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToIocEnrichment(row);
  }

  getIocsByAlertId(alertId: string): IOC[] {
    const alert = this.getAlertById(alertId);
    if (!alert) return [];

    const eventIds = alert.relatedEventIds || [];
    const ipValues = [alert.sourceIp, alert.destinationIp].filter(Boolean) as string[];

    const placeholders = eventIds.map(() => "?").join(",");
    let query = "SELECT * FROM ioc_records WHERE value IN (?, ?)";
    const params: any[] = [alert.sourceIp, alert.destinationIp || ""];

    if (eventIds.length > 0) {
      query += ` OR source_event_id IN (${placeholders})`;
      params.push(...eventIds);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToIoc(r));
  }

  getIocsByIncidentId(incidentId: string): IOC[] {
    const incident = this.getIncidentById(incidentId);
    if (!incident || !incident.alertIds || incident.alertIds.length === 0) {
      return [];
    }

    const allIocsMap = new Map<string, IOC>();
    for (const alertId of incident.alertIds) {
      const alertIocs = this.getIocsByAlertId(alertId);
      for (const ioc of alertIocs) {
        allIocsMap.set(ioc.id, ioc);
      }
    }
    return Array.from(allIocsMap.values());
  }

  // ------------------------------------------
  // DETECTION STRATEGIES REPOSITORY
  // ------------------------------------------

  insertDetectionStrategy(strategy: DetectionStrategy): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO detection_strategies (
        id, name, description, technique_id, technique_name, tactic,
        attack_version, analytic_conditions, required_telemetry,
        supported_platforms, severity, confidence_model, evidence_requirements,
        is_active, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?
      )
    `);

    const now = new Date().toISOString();
    stmt.run(
      strategy.id,
      strategy.name,
      strategy.description,
      strategy.techniqueId,
      strategy.techniqueName,
      strategy.tactic,
      strategy.attackVersion || "v15.1",
      safeJsonStringify(strategy.analyticConditions || []),
      safeJsonStringify(strategy.requiredTelemetry || []),
      safeJsonStringify(strategy.supportedPlatforms || ["Windows", "Linux"]),
      strategy.severity || "HIGH",
      safeJsonStringify(strategy.confidenceModel || { baseConfidence: "HIGH", minEvidenceCount: 1 }),
      safeJsonStringify(strategy.evidenceRequirements || []),
      strategy.isActive ? 1 : 0,
      strategy.createdAt || now,
      strategy.updatedAt || now
    );
  }

  getDetectionStrategyById(id: string): DetectionStrategy | null {
    const stmt = this.db.prepare("SELECT * FROM detection_strategies WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToDetectionStrategy(row);
  }

  listDetectionStrategies(filters: StrategyFilters = {}): DetectionStrategy[] {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.techniqueId) {
      conditions.push("technique_id = ?");
      params.push(filters.techniqueId);
    }
    if (filters.tactic) {
      conditions.push("UPPER(tactic) = UPPER(?)");
      params.push(filters.tactic);
    }
    if (filters.isActive !== undefined) {
      conditions.push("is_active = ?");
      params.push(filters.isActive ? 1 : 0);
    }
    if (filters.search) {
      conditions.push("(name LIKE ? OR description LIKE ? OR technique_id LIKE ?)");
      const term = `%${filters.search}%`;
      params.push(term, term, term);
    }

    let query = "SELECT * FROM detection_strategies";
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(" AND ")}`;
    }
    query += " ORDER BY id ASC";

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToDetectionStrategy(r));
  }

  // ------------------------------------------
  // CORRELATIONS REPOSITORY
  // ------------------------------------------

  insertCorrelation(correlation: CorrelationRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO correlations (
        id, strategy_id, analytic_id, strategy_name,
        matched_event_ids, matched_alert_ids, ioc_ids, incident_id,
        severity, confidence, risk_score, contributors,
        evidence, explanation, fingerprint, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?
      )
    `);

    const now = new Date().toISOString();
    stmt.run(
      correlation.id,
      correlation.strategyId,
      correlation.analyticId,
      correlation.strategyName || null,
      safeJsonStringify(correlation.matchedEventIds || []),
      safeJsonStringify(correlation.matchedAlertIds || []),
      safeJsonStringify(correlation.iocIds || []),
      correlation.incidentId || null,
      correlation.severity,
      correlation.confidence,
      correlation.riskScore || 0,
      safeJsonStringify(correlation.contributors || []),
      safeJsonStringify(correlation.evidence || {}),
      correlation.explanation,
      correlation.fingerprint,
      correlation.createdAt || now,
      correlation.updatedAt || now
    );
  }

  getCorrelationById(id: string): CorrelationRecord | null {
    const stmt = this.db.prepare("SELECT * FROM correlations WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToCorrelation(row);
  }

  getCorrelationByFingerprint(fingerprint: string): CorrelationRecord | null {
    const stmt = this.db.prepare("SELECT * FROM correlations WHERE fingerprint = ?");
    const row = stmt.get(fingerprint) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToCorrelation(row);
  }

  existsCorrelationFingerprint(fingerprint: string): boolean {
    const stmt = this.db.prepare("SELECT id FROM correlations WHERE fingerprint = ?");
    return Boolean(stmt.get(fingerprint));
  }

  listCorrelations(filters: CorrelationFilters = {}): {
    correlations: CorrelationRecord[];
    total: number;
    limit: number;
    offset: number;
  } {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.strategyId) {
      conditions.push("strategy_id = ?");
      params.push(filters.strategyId);
    }
    if (filters.severity) {
      conditions.push("UPPER(severity) = UPPER(?)");
      params.push(filters.severity);
    }
    if (filters.confidence) {
      conditions.push("UPPER(confidence) = UPPER(?)");
      params.push(filters.confidence);
    }
    if (filters.incidentId) {
      conditions.push("incident_id = ?");
      params.push(filters.incidentId);
    }
    if (filters.search) {
      conditions.push("(explanation LIKE ? OR strategy_name LIKE ?)");
      const term = `%${filters.search}%`;
      params.push(term, term);
    }

    const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";

    const countStmt = this.db.prepare(`SELECT COUNT(*) as total FROM correlations${whereClause}`);
    const countRow = countStmt.get(...params) as { total: number };
    const total = countRow ? countRow.total : 0;

    const limit = filters.limit !== undefined ? Math.max(1, filters.limit) : 50;
    const offset = filters.offset !== undefined ? Math.max(0, filters.offset) : 0;

    const selectQuery = `
      SELECT * FROM correlations
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `;

    const selectStmt = this.db.prepare(selectQuery);
    const rows = selectStmt.all(...params, limit, offset) as Record<string, unknown>[];

    return {
      correlations: rows.map((r) => this.mapRowToCorrelation(r)),
      total,
      limit,
      offset
    };
  }

  // ------------------------------------------
  // SOAR PLAYBOOKS REPOSITORY
  // ------------------------------------------

  insertPlaybook(playbook: SoarPlaybook): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO soar_playbooks (
        id, name, description, version, status,
        trigger_type, trigger_conditions, policy, actions,
        created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?
      )
    `);

    const now = new Date().toISOString();
    stmt.run(
      playbook.id,
      playbook.name,
      playbook.description,
      playbook.version || "1.0.0",
      playbook.status || "ENABLED",
      playbook.triggerType || "ALERT",
      safeJsonStringify(playbook.triggerConditions || {}),
      safeJsonStringify(playbook.policy || { requiresApproval: true }),
      safeJsonStringify(playbook.actions || []),
      playbook.createdAt || now,
      playbook.updatedAt || now
    );
  }

  updatePlaybook(id: string, updates: Partial<SoarPlaybook>): SoarPlaybook | null {
    const existing = this.getPlaybookById(id);
    if (!existing) return null;

    const updated: SoarPlaybook = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    const stmt = this.db.prepare(`
      UPDATE soar_playbooks SET
        name = ?,
        description = ?,
        version = ?,
        status = ?,
        trigger_type = ?,
        trigger_conditions = ?,
        policy = ?,
        actions = ?,
        updated_at = ?
      WHERE id = ?
    `);

    stmt.run(
      updated.name,
      updated.description,
      updated.version,
      updated.status,
      updated.triggerType,
      safeJsonStringify(updated.triggerConditions),
      safeJsonStringify(updated.policy),
      safeJsonStringify(updated.actions),
      updated.updatedAt,
      id
    );

    return updated;
  }

  getPlaybookById(id: string): SoarPlaybook | null {
    const stmt = this.db.prepare("SELECT * FROM soar_playbooks WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToPlaybook(row);
  }

  listPlaybooks(status?: string): SoarPlaybook[] {
    let query = "SELECT * FROM soar_playbooks";
    const params: any[] = [];

    if (status) {
      query += " WHERE UPPER(status) = UPPER(?)";
      params.push(status);
    }
    query += " ORDER BY name ASC";

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToPlaybook(r));
  }

  // ------------------------------------------
  // SOAR PLAYBOOK EXECUTIONS REPOSITORY
  // ------------------------------------------

  insertPlaybookExecution(execution: SoarPlaybookExecution): void {
    const stmt = this.db.prepare(`
      INSERT INTO soar_playbook_executions (
        id, playbook_id, playbook_name, playbook_version,
        incident_id, alert_id, correlation_id, initiating_user,
        status, approved_by, approved_at, rejection_reason,
        current_step_index, total_steps, steps_state,
        idempotency_key, created_at, updated_at, completed_at
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?
      )
    `);

    const now = new Date().toISOString();
    stmt.run(
      execution.id,
      execution.playbookId,
      execution.playbookName,
      execution.playbookVersion,
      execution.incidentId || null,
      execution.alertId || null,
      execution.correlationId || null,
      execution.initiatingUser,
      execution.status || "PENDING",
      execution.approvedBy || null,
      execution.approvedAt || null,
      execution.rejectionReason || null,
      execution.currentStepIndex || 0,
      execution.totalSteps || (execution.stepsState ? execution.stepsState.length : 0),
      safeJsonStringify(execution.stepsState || []),
      execution.idempotencyKey,
      execution.createdAt || now,
      execution.updatedAt || now,
      execution.completedAt || null
    );
  }

  updatePlaybookExecution(
    id: string,
    updates: Partial<SoarPlaybookExecution>
  ): SoarPlaybookExecution | null {
    const existing = this.getPlaybookExecutionById(id);
    if (!existing) return null;

    const merged: SoarPlaybookExecution = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    const stmt = this.db.prepare(`
      UPDATE soar_playbook_executions SET
        status = ?,
        approved_by = ?,
        approved_at = ?,
        rejection_reason = ?,
        current_step_index = ?,
        total_steps = ?,
        steps_state = ?,
        updated_at = ?,
        completed_at = ?
      WHERE id = ?
    `);

    stmt.run(
      merged.status,
      merged.approvedBy || null,
      merged.approvedAt || null,
      merged.rejectionReason || null,
      merged.currentStepIndex,
      merged.totalSteps,
      safeJsonStringify(merged.stepsState),
      merged.updatedAt,
      merged.completedAt || null,
      id
    );

    return merged;
  }

  getPlaybookExecutionById(id: string): SoarPlaybookExecution | null {
    const stmt = this.db.prepare("SELECT * FROM soar_playbook_executions WHERE id = ?");
    const row = stmt.get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToPlaybookExecution(row);
  }

  getPlaybookExecutionByIdempotencyKey(key: string): SoarPlaybookExecution | null {
    const stmt = this.db.prepare("SELECT * FROM soar_playbook_executions WHERE idempotency_key = ?");
    const row = stmt.get(key) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.mapRowToPlaybookExecution(row);
  }

  listPlaybookExecutions(filters: ExecutionFilters = {}): {
    executions: SoarPlaybookExecution[];
    total: number;
    limit: number;
    offset: number;
  } {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.playbookId) {
      conditions.push("playbook_id = ?");
      params.push(filters.playbookId);
    }
    if (filters.status) {
      conditions.push("UPPER(status) = UPPER(?)");
      params.push(filters.status);
    }
    if (filters.incidentId) {
      conditions.push("incident_id = ?");
      params.push(filters.incidentId);
    }
    if (filters.alertId) {
      conditions.push("alert_id = ?");
      params.push(filters.alertId);
    }
    if (filters.correlationId) {
      conditions.push("correlation_id = ?");
      params.push(filters.correlationId);
    }

    const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";

    const countStmt = this.db.prepare(`SELECT COUNT(*) as total FROM soar_playbook_executions${whereClause}`);
    const countRow = countStmt.get(...params) as { total: number };
    const total = countRow ? countRow.total : 0;

    const limit = filters.limit !== undefined ? Math.max(1, filters.limit) : 50;
    const offset = filters.offset !== undefined ? Math.max(0, filters.offset) : 0;

    const selectQuery = `
      SELECT * FROM soar_playbook_executions
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `;

    const selectStmt = this.db.prepare(selectQuery);
    const rows = selectStmt.all(...params, limit, offset) as Record<string, unknown>[];

    return {
      executions: rows.map((r) => this.mapRowToPlaybookExecution(r)),
      total,
      limit,
      offset
    };
  }

  // ------------------------------------------
  // SOAR AUDIT LOGS REPOSITORY
  // ------------------------------------------

  insertSoarAuditLog(log: SoarAuditLog): void {
    const stmt = this.db.prepare(`
      INSERT INTO soar_audit_logs (
        id, execution_id, incident_id, action_type,
        connector_id, target_type, target, actor,
        event_type, details, timestamp
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?
      )
    `);

    stmt.run(
      log.id,
      log.executionId || null,
      log.incidentId || null,
      log.actionType,
      log.connectorId,
      log.targetType,
      log.target,
      log.actor,
      log.eventType,
      typeof log.details === "string" ? log.details : safeJsonStringify(log.details || null),
      log.timestamp || new Date().toISOString()
    );
  }

  listSoarAuditLogs(filters: AuditLogFilters = {}): SoarAuditLog[] {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.executionId) {
      conditions.push("execution_id = ?");
      params.push(filters.executionId);
    }
    if (filters.incidentId) {
      conditions.push("incident_id = ?");
      params.push(filters.incidentId);
    }
    if (filters.actionType) {
      conditions.push("action_type = ?");
      params.push(filters.actionType);
    }
    if (filters.connectorId) {
      conditions.push("connector_id = ?");
      params.push(filters.connectorId);
    }

    let query = "SELECT * FROM soar_audit_logs";
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(" AND ")}`;
    }
    query += " ORDER BY timestamp DESC";

    if (filters.limit) {
      query += " LIMIT ?";
      params.push(Math.max(1, filters.limit));
      if (filters.offset) {
        query += " OFFSET ?";
        params.push(Math.max(0, filters.offset));
      }
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToSoarAuditLog(r));
  }

  // ------------------------------------------
  // ROW MAPPERS
  // ------------------------------------------

  private mapRowToAlert(r: Record<string, unknown>): Alert {
    return {
      id: String(r.id),
      title: String(r.title),
      severity: String(r.severity) as Alert["severity"],
      riskScore: Number(r.risk_score),
      status: String(r.status) as Alert["status"],
      host: String(r.host),
      sourceIp: String(r.source_ip),
      destinationIp: r.destination_ip ? String(r.destination_ip) : undefined,
      username: String(r.username),
      detectionSource: String(r.detection_source) as Alert["detectionSource"],
      ruleId: r.rule_id ? String(r.rule_id) : undefined,
      ruleName: r.rule_name ? String(r.rule_name) : undefined,
      detectionConfidence: Number(r.detection_confidence),
      aiConfidence: r.ai_confidence ? Number(r.ai_confidence) : undefined,
      description: String(r.description || ""),
      evidence: safeJsonParse<string[]>(r.evidence as string, []),
      relatedEventIds: safeJsonParse<string[]>(r.related_event_ids as string, []),
      mitreTechniques: safeJsonParse<MitreTechnique[]>(r.mitre_techniques as string, []),
      assignedTo: r.assigned_to ? String(r.assigned_to) : undefined,
      notes: r.analyst_notes ? String(r.analyst_notes) : undefined,
      geminiAnalysis: safeJsonParse<GeminiInvestigationResult | undefined>(
        r.gemini_analysis as string,
        undefined
      ),
      timestamp: String(r.created_at),
      updatedAt: String(r.updated_at)
    };
  }

  private mapRowToSecurityEvent(r: Record<string, unknown>): SecurityEvent {
    return {
      id: String(r.id),
      timestamp: String(r.timestamp),
      event_type: String(r.event_type),
      source_ip: String(r.source_ip),
      destination_ip: String(r.destination_ip),
      source_port: r.source_port ? Number(r.source_port) : undefined,
      destination_port: r.destination_port ? Number(r.destination_port) : undefined,
      hostname: String(r.hostname),
      username: String(r.username),
      process: r.process_name ? String(r.process_name) : undefined,
      action: String(r.action) as SecurityEvent["action"],
      status: String(r.status) as SecurityEvent["status"],
      severity: String(r.severity) as SecurityEvent["severity"],
      message: String(r.message),
      raw: String(r.raw_text),
      metadata: safeJsonParse<Record<string, any>>(r.metadata as string, {})
    };
  }

  private mapRowToIncident(r: Record<string, unknown>): IncidentRecord {
    return {
      id: String(r.id),
      title: String(r.title),
      severity: String(r.severity),
      status: String(r.status),
      priority: r.priority ? String(r.priority) : "P2",
      leadAnalyst: r.lead_analyst ? String(r.lead_analyst) : undefined,
      alertIds: safeJsonParse<string[]>(r.alert_ids as string, []),
      executiveSummary: r.executive_summary ? String(r.executive_summary) : undefined,
      containmentActions: safeJsonParse<string[]>(r.containment_actions as string, []),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at),
      closedAt: r.closed_at ? String(r.closed_at) : undefined,
      closedBy: r.closed_by ? String(r.closed_by) : undefined,
      closureSummary: r.closure_summary ? String(r.closure_summary) : undefined
    };
  }

  private mapRowToIoc(r: Record<string, unknown>): IOC {
    return {
      id: String(r.id),
      type: String(r.type) as IOC["type"],
      value: String(r.value),
      defangedValue: String(r.defanged_value),
      riskLevel: String(r.threat_level) as IOC["riskLevel"],
      context: String(r.context || ""),
      sourceEventId: r.source_event_id ? String(r.source_event_id) : undefined,
      confidence: Number(r.confidence || 0),
      firstSeen: String(r.first_seen),
      lastSeen: r.last_seen ? String(r.last_seen) : undefined,
      tags: safeJsonParse<string[]>(r.tags as string, [])
    };
  }

  private mapRowToIocEnrichment(r: Record<string, unknown>): IocEnrichmentRecord {
    return {
      id: String(r.id),
      iocId: String(r.ioc_id),
      provider: String(r.provider),
      reputation: (String(r.reputation) as IocEnrichmentRecord["reputation"]) || "UNKNOWN",
      threatLevel: (String(r.threat_level) as IocEnrichmentRecord["threatLevel"]) || "UNKNOWN",
      confidence: Number(r.confidence || 0),
      classification: r.classification ? String(r.classification) : undefined,
      firstSeen: r.first_seen ? String(r.first_seen) : undefined,
      lastSeen: r.last_seen ? String(r.last_seen) : undefined,
      enrichedAt: String(r.enriched_at),
      source: r.source ? String(r.source) : undefined,
      summary: String(r.summary || ""),
      metadata: safeJsonParse<Record<string, unknown> | null>(r.metadata as string, null),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at)
    };
  }

  private mapRowToIncidentAction(r: Record<string, unknown>): IncidentResponseActionRecord {
    return {
      id: String(r.id),
      incidentId: String(r.incident_id),
      actionType: String(r.action_type),
      targetType: String(r.target_type),
      target: String(r.target),
      status: String(r.status),
      requestedBy: String(r.requested_by),
      approvedBy: r.approved_by ? String(r.approved_by) : undefined,
      requestedAt: String(r.requested_at),
      approvedAt: r.approved_at ? String(r.approved_at) : undefined,
      executedAt: r.executed_at ? String(r.executed_at) : undefined,
      result: r.result ? String(r.result) : undefined,
      notes: r.notes ? String(r.notes) : undefined,
      metadata: safeJsonParse<Record<string, unknown> | null>(r.metadata as string, null),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at)
    };
  }

  private mapRowToDetectionStrategy(r: Record<string, unknown>): DetectionStrategy {
    return {
      id: String(r.id),
      name: String(r.name),
      description: String(r.description),
      techniqueId: String(r.technique_id),
      techniqueName: String(r.technique_name),
      tactic: String(r.tactic),
      attackVersion: String(r.attack_version || "v15.1"),
      analyticConditions: safeJsonParse<string[]>(r.analytic_conditions as string, []),
      requiredTelemetry: safeJsonParse<string[]>(r.required_telemetry as string, []),
      supportedPlatforms: safeJsonParse<string[]>(r.supported_platforms as string, ["Windows", "Linux"]),
      severity: String(r.severity) as DetectionStrategy["severity"],
      confidenceModel: safeJsonParse<DetectionStrategy["confidenceModel"]>(
        r.confidence_model as string,
        { baseConfidence: "HIGH", minEvidenceCount: 1 }
      ),
      evidenceRequirements: safeJsonParse<string[]>(r.evidence_requirements as string, []),
      isActive: Boolean(r.is_active),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at)
    };
  }

  private mapRowToCorrelation(r: Record<string, unknown>): CorrelationRecord {
    return {
      id: String(r.id),
      strategyId: String(r.strategy_id),
      analyticId: String(r.analytic_id),
      strategyName: r.strategy_name ? String(r.strategy_name) : undefined,
      matchedEventIds: safeJsonParse<string[]>(r.matched_event_ids as string, []),
      matchedAlertIds: safeJsonParse<string[]>(r.matched_alert_ids as string, []),
      iocIds: safeJsonParse<string[]>(r.ioc_ids as string, []),
      incidentId: r.incident_id ? String(r.incident_id) : undefined,
      severity: String(r.severity) as CorrelationRecord["severity"],
      confidence: String(r.confidence) as CorrelationRecord["confidence"],
      riskScore: Number(r.risk_score || 0),
      contributors: safeJsonParse<RiskContributor[]>(r.contributors as string, []),
      evidence: safeJsonParse<CorrelationEvidence>(r.evidence as string, {
        eventIds: [],
        alertIds: [],
        iocIds: [],
        timestamps: [],
        hosts: [],
        users: [],
        sourceIps: []
      }),
      explanation: String(r.explanation || ""),
      fingerprint: String(r.fingerprint),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at)
    };
  }

  private mapRowToPlaybook(r: Record<string, unknown>): SoarPlaybook {
    return {
      id: String(r.id),
      name: String(r.name),
      description: String(r.description),
      version: String(r.version || "1.0.0"),
      status: String(r.status) as SoarPlaybook["status"],
      triggerType: String(r.trigger_type) as SoarPlaybook["triggerType"],
      triggerConditions: safeJsonParse<Record<string, unknown>>(r.trigger_conditions as string, {}),
      policy: safeJsonParse<SoarPlaybook["policy"]>(r.policy as string, { requiresApproval: true }),
      actions: safeJsonParse<SoarPlaybook["actions"]>(r.actions as string, []),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at)
    };
  }

  private mapRowToPlaybookExecution(r: Record<string, unknown>): SoarPlaybookExecution {
    return {
      id: String(r.id),
      playbookId: String(r.playbook_id),
      playbookName: String(r.playbook_name),
      playbookVersion: String(r.playbook_version || "1.0.0"),
      incidentId: r.incident_id ? String(r.incident_id) : undefined,
      alertId: r.alert_id ? String(r.alert_id) : undefined,
      correlationId: r.correlation_id ? String(r.correlation_id) : undefined,
      initiatingUser: String(r.initiating_user),
      status: String(r.status) as SoarPlaybookExecution["status"],
      approvedBy: r.approved_by ? String(r.approved_by) : undefined,
      approvedAt: r.approved_at ? String(r.approved_at) : undefined,
      rejectionReason: r.rejection_reason ? String(r.rejection_reason) : undefined,
      currentStepIndex: Number(r.current_step_index || 0),
      totalSteps: Number(r.total_steps || 0),
      stepsState: safeJsonParse<PlaybookStepState[]>(r.steps_state as string, []),
      idempotencyKey: String(r.idempotency_key),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at),
      completedAt: r.completed_at ? String(r.completed_at) : undefined
    };
  }

  private mapRowToSoarAuditLog(r: Record<string, unknown>): SoarAuditLog {
    return {
      id: String(r.id),
      executionId: r.execution_id ? String(r.execution_id) : undefined,
      incidentId: r.incident_id ? String(r.incident_id) : undefined,
      actionType: String(r.action_type),
      connectorId: String(r.connector_id),
      targetType: String(r.target_type),
      target: String(r.target),
      actor: String(r.actor),
      eventType: String(r.event_type) as SoarAuditLog["eventType"],
      details: safeJsonParse<Record<string, unknown> | string>(r.details as string, String(r.details || "")),
      timestamp: String(r.timestamp)
    };
  }
}
