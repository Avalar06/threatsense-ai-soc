import { IOC } from "../types/soc.js";

// Defanging utility
export function defangIoc(val: string, type: IOC["type"]): string {
  if (type === "URL") {
    return val
      .replace(/^http:\/\//i, "hxxp://")
      .replace(/^https:\/\//i, "hxxps://")
      .replace(/\./g, "[.]");
  }
  if (type === "DOMAIN" || type === "IPV4" || type === "IPV6") {
    return val.replace(/\./g, "[.]");
  }
  return val;
}

export function extractIocsFromText(text: string, sourceEventId?: string): IOC[] {
  if (!text || !text.trim()) return [];

  const foundIocs: Map<string, IOC> = new Map();

  // 1. IPv4 Regex (exclude common private broadcast or invalid)
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const ipv4Matches = text.match(ipv4Regex) || [];
  for (const ip of ipv4Matches) {
    if (ip === "0.0.0.0" || ip === "255.255.255.255") continue;
    const isPrivate = isPrivateIp(ip);
    const key = `IPV4:${ip}`;
    if (!foundIocs.has(key)) {
      const riskLevel: IOC["riskLevel"] = isPrivate
        ? "BENIGN"
        : isKnownMaliciousIp(ip)
        ? "MALICIOUS"
        : "SUSPICIOUS";
      foundIocs.set(key, {
        id: `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        value: ip,
        defangedValue: defangIoc(ip, "IPV4"),
        type: "IPV4",
        riskLevel,
        context: isPrivate ? "Internal Corporate Subnet" : "External Public IP Address",
        sourceEventId,
        confidence: isPrivate ? 95 : riskLevel === "MALICIOUS" ? 92 : 75,
        firstSeen: new Date().toISOString(),
        tags: [isPrivate ? "RFC1918" : "External", "Network"],
      });
    }
  }

  // 2. URLs
  const urlRegex = /\bhttps?:\/\/[^\s"'<>]+/gi;
  const urlMatches = text.match(urlRegex) || [];
  for (const rawUrl of urlMatches) {
    const cleanUrl = rawUrl.replace(/[),.;]+$/, "");
    const key = `URL:${cleanUrl}`;
    if (!foundIocs.has(key)) {
      const isMal = cleanUrl.includes("evil") || cleanUrl.includes("portal-auth") || cleanUrl.includes("stage2") || cleanUrl.includes("cmd.php");
      foundIocs.set(key, {
        id: `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        value: cleanUrl,
        defangedValue: defangIoc(cleanUrl, "URL"),
        type: "URL",
        riskLevel: isMal ? "MALICIOUS" : "SUSPICIOUS",
        context: "HTTP/HTTPS Endpoint referenced in payload",
        sourceEventId,
        confidence: isMal ? 95 : 80,
        firstSeen: new Date().toISOString(),
        tags: ["Web", "Payload-Lure"],
      });
    }
  }

  // 3. Domain Names
  const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|ru|cc|top|xyz|biz|info|site|cn)\b/gi;
  const domainMatches = text.match(domainRegex) || [];
  for (const domain of domainMatches) {
    const dLower = domain.toLowerCase();
    if (dLower.endsWith(".exe") || dLower.endsWith(".dll") || dLower.endsWith(".log") || dLower.endsWith(".php")) continue;
    const key = `DOMAIN:${dLower}`;
    if (!foundIocs.has(key)) {
      const isMal = dLower.includes("evil") || dLower.includes("portal-auth") || dLower.includes("notice-m365") || dLower.includes("security-verify");
      foundIocs.set(key, {
        id: `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        value: dLower,
        defangedValue: defangIoc(dLower, "DOMAIN"),
        type: "DOMAIN",
        riskLevel: isMal ? "MALICIOUS" : "SUSPICIOUS",
        context: isMal ? "Attacker C2 or Phishing Infrastructure Domain" : "FQDN Observed in Telemetry",
        sourceEventId,
        confidence: isMal ? 90 : 70,
        firstSeen: new Date().toISOString(),
        tags: ["DNS", "Domain"],
      });
    }
  }

  // 4. SHA-256 Hashes
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  const sha256Matches = text.match(sha256Regex) || [];
  for (const hash of sha256Matches) {
    const key = `HASH_SHA256:${hash.toLowerCase()}`;
    if (!foundIocs.has(key)) {
      foundIocs.set(key, {
        id: `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        value: hash.toLowerCase(),
        defangedValue: hash.toLowerCase(),
        type: "HASH_SHA256",
        riskLevel: "MALICIOUS",
        context: "SHA-256 Binary / File Hash Signature",
        sourceEventId,
        confidence: 90,
        firstSeen: new Date().toISOString(),
        tags: ["Cryptographic Hash", "File Identification"],
      });
    }
  }

  // 5. MD5 Hashes
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const md5Matches = text.match(md5Regex) || [];
  for (const hash of md5Matches) {
    const key = `HASH_MD5:${hash.toLowerCase()}`;
    if (!foundIocs.has(key)) {
      foundIocs.set(key, {
        id: `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        value: hash.toLowerCase(),
        defangedValue: hash.toLowerCase(),
        type: "HASH_MD5",
        riskLevel: "SUSPICIOUS",
        context: "MD5 File Hash Checksum",
        sourceEventId,
        confidence: 85,
        firstSeen: new Date().toISOString(),
        tags: ["MD5", "Hash"],
      });
    }
  }

  // 6. Suspicious File Paths (Windows and Linux)
  const filePathRegex = /(?:[a-zA-Z]:\\[^ \t\r\n"'`<>]+|\/(?:etc|var|tmp|home|usr|opt|bin|ProgramData|Windows)\/[^ \t\r\n"'`<>]+)/g;
  const pathMatches = text.match(filePathRegex) || [];
  for (const path of pathMatches) {
    const cleanPath = path.replace(/[),.;]+$/, "");
    const key = `FILE_PATH:${cleanPath}`;
    if (!foundIocs.has(key)) {
      const isMal = cleanPath.includes("mimi.dll") || cleanPath.includes("cmd.php") || cleanPath.includes("updater.exe") || cleanPath.includes("/etc/shadow");
      foundIocs.set(key, {
        id: `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        value: cleanPath,
        defangedValue: cleanPath,
        type: "FILE_PATH",
        riskLevel: isMal ? "MALICIOUS" : "SUSPICIOUS",
        context: "File System Path accessed by execution",
        sourceEventId,
        confidence: isMal ? 90 : 75,
        firstSeen: new Date().toISOString(),
        tags: ["Filesystem", "Artifact"],
      });
    }
  }

  // 7. Email Addresses
  const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
  const emailMatches = text.match(emailRegex) || [];
  for (const email of emailMatches) {
    const key = `EMAIL:${email.toLowerCase()}`;
    if (!foundIocs.has(key)) {
      const isPhish = email.includes("microsoft-security-verify.com") || email.includes("secureserver-notice-m365.com");
      foundIocs.set(key, {
        id: `IOC-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        value: email.toLowerCase(),
        defangedValue: email.toLowerCase().replace("@", "[at]").replace(/\./g, "[.]"),
        type: "EMAIL",
        riskLevel: isPhish ? "MALICIOUS" : "SUSPICIOUS",
        context: isPhish ? "Phishing Sender / Reply-To Address" : "Email Address Observed in Telemetry",
        sourceEventId,
        confidence: isPhish ? 95 : 80,
        firstSeen: new Date().toISOString(),
        tags: ["Email", "Messaging"],
      });
    }
  }

  return Array.from(foundIocs.values());
}

function isPrivateIp(ip: string): boolean {
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")) return true;
  if (ip.startsWith("172.")) {
    const secondOctet = parseInt(ip.split(".")[1], 10);
    return secondOctet >= 16 && secondOctet <= 31;
  }
  return false;
}

function isKnownMaliciousIp(ip: string): boolean {
  const knownBad = [
    "185.220.101.5",
    "194.26.29.112",
    "45.154.255.82",
    "103.208.220.12",
    "193.142.146.88",
    "198.51.100.23",
  ];
  return knownBad.includes(ip);
}
