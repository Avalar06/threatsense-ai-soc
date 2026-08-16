import { SecurityEvent, Severity } from "../types/soc.js";

// Helper to generate unique IDs
let eventCounter = 1000;
export function generateEventId(): string {
  eventCounter += 1;
  return `EVT-${Date.now().toString(36).toUpperCase()}-${eventCounter}`;
}

export function parseRawLogs(rawText: string, defaultHost = "CORP-ENDPOINT-01"): SecurityEvent[] {
  if (!rawText || !rawText.trim()) return [];

  const lines = rawText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));

  const events: SecurityEvent[] = [];

  for (const line of lines) {
    // Check if line is CSV format
    if (line.includes(",") && (line.includes("timestamp") || line.includes("src_ip") || events.length > 0 && lines[0].includes(","))) {
      const csvEvent = parseCsvLine(line, lines[0]);
      if (csvEvent) {
        events.push(csvEvent);
        continue;
      }
    }

    // Key-value / Syslog / Windows format parsing
    const event = parseStructuredLine(line, defaultHost);
    if (event) {
      events.push(event);
    }
  }

  return events;
}

function parseStructuredLine(line: string, defaultHost: string): SecurityEvent {
  const id = generateEventId();
  const nowIso = new Date().toISOString();

  // Extract timestamp if available
  let timestamp = nowIso;
  const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)/);
  const syslogDateMatch = line.match(/^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})/);

  if (isoMatch) {
    timestamp = isoMatch[1].replace(" ", "T");
    if (!timestamp.endsWith("Z") && !timestamp.includes("+")) timestamp += "Z";
  } else if (syslogDateMatch) {
    const currentYear = new Date().getFullYear();
    timestamp = new Date(`${syslogDateMatch[1]} ${currentYear} UTC`).toISOString();
  }

  // Extract key-value pairs
  const kv: Record<string, string> = {};
  const kvRegex = /([a-zA-Z0-9_\-\.]+)=("([^"]*)"|'([^']*)'|([^\s]+))/g;
  let match;
  while ((match = kvRegex.exec(line)) !== null) {
    const key = match[1].toLowerCase();
    const val = match[3] ?? match[4] ?? match[5] ?? "";
    kv[key] = val;
  }

  // Extract IPs with regex fallback
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const foundIps = line.match(ipRegex) || [];

  const source_ip = kv.src_ip || kv.src || kv.source_ip || kv.client_ip || foundIps[0] || "127.0.0.1";
  const destination_ip = kv.dst_ip || kv.dst || kv.destination_ip || kv.dest_ip || (foundIps.length > 1 ? foundIps[1] : "10.0.0.1");

  const source_port = kv.src_port ? parseInt(kv.src_port, 10) : undefined;
  const destination_port = kv.dst_port ? parseInt(kv.dst_port, 10) : undefined;

  // Extract Username
  let username = kv.user || kv.username || kv.usr || kv.account || "system";
  if (username === "system" && line.includes("user=")) {
    const uMatch = line.match(/user=([^\s]+)/i);
    if (uMatch) username = uMatch[1].replace(/['"]/g, "");
  } else if (username === "system" && line.includes("for invalid user")) {
    const invMatch = line.match(/for invalid user ([^\s]+)/i);
    if (invMatch) username = invMatch[1];
  } else if (username === "system" && line.includes("Accepted password for")) {
    const accMatch = line.match(/Accepted password for ([^\s]+)/i);
    if (accMatch) username = accMatch[1];
  } else if (username === "system" && line.includes("Failed password for")) {
    const failMatch = line.match(/Failed password for ([^\s]+)/i);
    if (failMatch) username = failMatch[1];
  }

  // Extract Hostname
  const hostname = kv.host || kv.hostname || kv.computer || defaultHost;

  // Extract Process
  let process = kv.process || kv.proc || kv.image || kv.app || "";
  if (!process) {
    if (line.includes("powershell")) process = "powershell.exe";
    else if (line.includes("sshd")) process = "sshd";
    else if (line.includes("sudo")) process = "sudo";
    else if (line.includes("rundll32")) process = "rundll32.exe";
    else if (line.includes("cmd.exe")) process = "cmd.exe";
    else if (line.includes("nginx") || line.includes("GET ") || line.includes("POST ")) process = "nginx";
    else process = "system";
  }

  // Action and Status determination
  let action: SecurityEvent["action"] = "UNKNOWN";
  let status: SecurityEvent["status"] = "SUCCESS";
  let severity: Severity = "INFORMATIONAL";

  const lowerLine = line.toLowerCase();

  if (lowerLine.includes("fail") || lowerLine.includes("drop") || lowerLine.includes("block") || lowerLine.includes("error") || lowerLine.includes("denied") || lowerLine.includes("eventid=4625")) {
    status = "FAILURE";
    action = lowerLine.includes("drop") || lowerLine.includes("block") ? "BLOCK" : "LOGIN_FAIL";
    severity = "MEDIUM";
  }

  if (lowerLine.includes("accept") || lowerLine.includes("success") || lowerLine.includes("allow") || lowerLine.includes("eventid=4624")) {
    status = "SUCCESS";
    action = lowerLine.includes("allow") ? "ALLOW" : "LOGIN_SUCCESS";
    severity = "INFORMATIONAL";
  }

  if (lowerLine.includes("encodedcommand") || lowerLine.includes("dumplsass") || lowerLine.includes("mimikatz") || lowerLine.includes("cobaltstrike") || lowerLine.includes("web shell") || lowerLine.includes("eventid=7045")) {
    status = "FLAGGED";
    severity = "CRITICAL";
    action = "EXECUTE";
  } else if (lowerLine.includes("sudo") || lowerLine.includes("privilege") || lowerLine.includes("eventid=4672") || lowerLine.includes("domain admins")) {
    status = "ANOMALOUS";
    severity = "HIGH";
    action = "ESCALATE";
  }

  // Event Type categorization
  let event_type = "SYSTEM_LOG";
  if (lowerLine.includes("sshd") || lowerLine.includes("login") || lowerLine.includes("logon") || lowerLine.includes("auth") || lowerLine.includes("4624") || lowerLine.includes("4625")) {
    event_type = status === "FAILURE" ? "AUTH_FAILURE" : "AUTH_SUCCESS";
  } else if (lowerLine.includes("sudo") || lowerLine.includes("4672") || lowerLine.includes("privilege")) {
    event_type = "PRIVILEGE_ESCALATE";
  } else if (lowerLine.includes("powershell") || lowerLine.includes("cmd.exe") || lowerLine.includes("4688") || lowerLine.includes("process")) {
    event_type = "PROCESS_CREATE";
  } else if (lowerLine.includes("drop") || lowerLine.includes("syn") || lowerLine.includes("tcp") || lowerLine.includes("outbound") || lowerLine.includes("connect")) {
    event_type = "NETWORK_CONNECT";
  } else if (lowerLine.includes("get ") || lowerLine.includes("post ") || lowerLine.includes("http")) {
    event_type = "HTTP_REQUEST";
  } else if (lowerLine.includes("service") || lowerLine.includes("7045")) {
    event_type = "SERVICE_CREATE";
  }

  // Extract message
  let message = kv.msg || kv.message || line;
  if (message.length > 200 && !kv.msg) {
    message = line.substring(0, 197) + "...";
  }

  return {
    id,
    timestamp,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    username,
    hostname,
    process,
    event_type,
    action,
    status,
    message,
    severity,
    raw: line,
    metadata: kv,
  };
}

function parseCsvLine(line: string, headerLine: string): SecurityEvent | null {
  if (line === headerLine) return null;
  const headers = headerLine.split(",").map((h) => h.trim().toLowerCase());
  const cols = line.split(",").map((c) => c.trim().replace(/^["']|["']$/g, ""));

  if (cols.length < 2) return null;

  const data: Record<string, string> = {};
  headers.forEach((h, i) => {
    data[h] = cols[i] || "";
  });

  return {
    id: generateEventId(),
    timestamp: data.timestamp || new Date().toISOString(),
    source_ip: data.source_ip || data.src_ip || data.src || "127.0.0.1",
    destination_ip: data.destination_ip || data.dst_ip || data.dst || "10.0.0.1",
    source_port: data.source_port ? parseInt(data.source_port, 10) : undefined,
    destination_port: data.destination_port ? parseInt(data.destination_port, 10) : undefined,
    username: data.username || data.user || "system",
    hostname: data.hostname || data.host || "CORP-ENDPOINT",
    process: data.process || data.app || "system",
    event_type: data.event_type || data.type || "GENERIC_EVENT",
    action: (data.action as any) || "UNKNOWN",
    status: (data.status as any) || "SUCCESS",
    message: data.message || data.msg || line,
    severity: (data.severity as any) || "INFORMATIONAL",
    raw: line,
    metadata: data,
  };
}
