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
import type {
  Alert,
  SecurityEvent,
  IncidentReport,
  IOC,
  MitreTechnique,
  GeminiInvestigationResult,
  IncidentResponseAction
} from "../../src/types/soc.js";

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
        created_at, updated_at, closed_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?
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
      incident.closedAt ?? null
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
        closed_at = ?
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
  // IOC RECORDS REPOSITORY
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
      now,
      safeJsonStringify(ioc.tags ?? [])
    );
  }

  getAllIocs(): IOC[] {
    const stmt = this.db.prepare("SELECT * FROM ioc_records ORDER BY first_seen DESC");
    const rows = stmt.all() as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToIoc(r));
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
      closedAt: r.closed_at ? String(r.closed_at) : undefined
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
      tags: safeJsonParse<string[]>(r.tags as string, [])
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
}
