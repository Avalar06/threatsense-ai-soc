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
  GeminiInvestigationResult
} from "../../src/types/soc.js";

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

export const DEFAULT_DB_PATH = path.join(process.cwd(), "data", "threatsense.db");

let activeDbInstance: DatabaseSync | null = null;

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

  constructor(db?: DatabaseSync) {
    this.db = db || getDatabase();
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
      null, // assigned_to
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

  getAllAlerts(): Alert[] {
    const stmt = this.db.prepare("SELECT * FROM alerts ORDER BY created_at DESC");
    const rows = stmt.all() as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToAlert(r));
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

  getAllIncidents(): IncidentRecord[] {
    const stmt = this.db.prepare("SELECT * FROM incidents ORDER BY created_at DESC");
    const rows = stmt.all() as Record<string, unknown>[];
    return rows.map((r) => this.mapRowToIncident(r));
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

  getAllReports(): IncidentReport[] {
    const stmt = this.db.prepare("SELECT * FROM incident_reports ORDER BY created_at DESC");
    const rows = stmt.all() as Record<string, unknown>[];
    return rows
      .map((r) => safeJsonParse<IncidentReport | null>(r.report_data as string, null))
      .filter((r): r is IncidentReport => r !== null);
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
}
