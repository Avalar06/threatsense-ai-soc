/**
 * ThreatSense AI - IOC Enrichment & Threat Intelligence Service
 * 
 * Provides a provider abstraction for external and local threat intelligence enrichment.
 * 
 * CRITICAL SAFETY REQUIREMENTS:
 * - SAFE DEMO MODE: When no external threat intelligence API key is configured (e.g. VirusTotal, AbuseIPDB),
 *   the service returns a structured "NOT_CONFIGURED" status with UNKNOWN threat level and 0 confidence.
 * - NEVER fabricate external threat reputation, false positives, or fake intelligence.
 * - Caching with TTL prevents unnecessary duplicate external provider queries.
 * - Parameterized operations and strict input sanitization.
 */

import type { IOC, IocEnrichment } from "../../src/types/soc.js";

export interface EnrichmentResult {
  provider: string;
  reputation: "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "UNKNOWN";
  threatLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  confidence: number; // 0 - 100
  classification?: string;
  firstSeen?: string;
  lastSeen?: string;
  source?: string;
  summary: string;
  metadata?: Record<string, unknown>;
  status: "ENRICHED" | "NOT_CONFIGURED" | "UNAVAILABLE" | "FAILED";
}

export interface IOCEnrichmentProvider {
  readonly name: string;
  isConfigured(): boolean;
  enrich(ioc: IOC): Promise<EnrichmentResult>;
}

/**
 * Standard Multi-Provider Threat Intelligence Service
 */
export class ThreatIntelEnrichmentService {
  private defaultTtlMs: number;

  constructor(defaultTtlHours: number = 24) {
    this.defaultTtlMs = defaultTtlHours * 60 * 60 * 1000;
  }

  /**
   * Determine if any live external threat intelligence provider is configured.
   */
  hasConfiguredExternalProvider(): boolean {
    return Boolean(
      process.env.ABUSEIPDB_API_KEY ||
      process.env.VIRUSTOTAL_API_KEY ||
      process.env.OTX_API_KEY
    );
  }

  /**
   * Enrich an indicator of compromise according to strict security and demo rules.
   */
  async enrichIoc(
    ioc: IOC,
    existingEnrichment?: IocEnrichment | null,
    forceRefresh: boolean = false
  ): Promise<EnrichmentResult> {
    const now = Date.now();

    // 1. Check cache TTL if an existing enrichment exists and forceRefresh is false
    if (
      !forceRefresh &&
      existingEnrichment &&
      existingEnrichment.status === "ENRICHED"
    ) {
      const enrichedTime = new Date(existingEnrichment.enrichedAt).getTime();
      if (!isNaN(enrichedTime) && now - enrichedTime < this.defaultTtlMs) {
        return {
          provider: existingEnrichment.provider,
          reputation: existingEnrichment.reputation,
          threatLevel: existingEnrichment.threatLevel,
          confidence: existingEnrichment.confidence,
          classification: existingEnrichment.classification,
          firstSeen: existingEnrichment.firstSeen,
          lastSeen: existingEnrichment.lastSeen,
          source: existingEnrichment.source || "Cache (Local SQLite)",
          summary: existingEnrichment.summary,
          metadata: (existingEnrichment.metadata as Record<string, unknown>) || {},
          status: "ENRICHED",
        };
      }
    }

    // 2. If no external provider is configured in environment, return transparent NOT_CONFIGURED state
    if (!this.hasConfiguredExternalProvider()) {
      return {
        provider: "NO_PROVIDER",
        reputation: "UNKNOWN",
        threatLevel: "UNKNOWN",
        confidence: 0,
        classification: "UNVERIFIED",
        summary: `Enrichment provider is not configured for ${ioc.type} indicator (${ioc.defangedValue || ioc.value}). External threat intelligence lookups require configuring ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, or OTX_API_KEY in environment variables.`,
        source: "ThreatSense Engine (Demo Mode)",
        metadata: {
          configured: false,
          iocType: ioc.type,
          unverified: true,
        },
        status: "NOT_CONFIGURED",
      };
    }

    // 3. Live external enrichment logic when credentials are provided
    try {
      if (process.env.ABUSEIPDB_API_KEY && (ioc.type === "IPV4" || ioc.type === "IPV6")) {
        return await this.enrichWithAbuseIPDB(ioc);
      } else if (process.env.VIRUSTOTAL_API_KEY) {
        return await this.enrichWithVirusTotal(ioc);
      }

      return {
        provider: "EXTERNAL_PROVIDER",
        reputation: "UNKNOWN",
        threatLevel: "UNKNOWN",
        confidence: 0,
        summary: `No compatible external provider found for IOC type '${ioc.type}'.`,
        status: "UNAVAILABLE",
      };
    } catch (err: any) {
      return {
        provider: "EXTERNAL_PROVIDER",
        reputation: "UNKNOWN",
        threatLevel: "UNKNOWN",
        confidence: 0,
        summary: `External provider request failed: ${err.message || "Unknown communication error"}`,
        status: "FAILED",
        metadata: {
          error: String(err.message || err),
        },
      };
    }
  }

  private async enrichWithAbuseIPDB(ioc: IOC): Promise<EnrichmentResult> {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
      throw new Error("ABUSEIPDB_API_KEY is not defined");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
      const res = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc.value)}&maxAgeInDays=90`,
        {
          headers: {
            Key: apiKey,
            Accept: "application/json",
          },
          signal: controller.signal,
        }
      );

      if (!res.ok) {
        throw new Error(`AbuseIPDB returned HTTP ${res.status}`);
      }

      const json = (await res.json()) as any;
      const data = json?.data || {};
      const score = Number(data.abuseConfidenceScore || 0);

      let reputation: EnrichmentResult["reputation"] = "UNKNOWN";
      let threatLevel: EnrichmentResult["threatLevel"] = "UNKNOWN";

      if (score >= 75) {
        reputation = "MALICIOUS";
        threatLevel = "CRITICAL";
      } else if (score >= 25) {
        reputation = "SUSPICIOUS";
        threatLevel = "HIGH";
      } else if (score > 0) {
        reputation = "SUSPICIOUS";
        threatLevel = "MEDIUM";
      } else {
        reputation = "BENIGN";
        threatLevel = "LOW";
      }

      return {
        provider: "AbuseIPDB",
        reputation,
        threatLevel,
        confidence: score,
        classification: data.usageType || data.domain || "IP Telemetry",
        firstSeen: data.lastReportedAt || undefined,
        lastSeen: data.lastReportedAt || undefined,
        source: "AbuseIPDB v2 Live API",
        summary: `AbuseIPDB Confidence Score: ${score}%. Total reports: ${data.totalReports || 0}. Country: ${data.countryCode || "N/A"}. ISP: ${data.isp || "N/A"}.`,
        metadata: {
          countryCode: data.countryCode,
          isp: data.isp,
          domain: data.domain,
          totalReports: data.totalReports,
          numDistinctUsers: data.numDistinctUsers,
        },
        status: "ENRICHED",
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private async enrichWithVirusTotal(ioc: IOC): Promise<EnrichmentResult> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      throw new Error("VIRUSTOTAL_API_KEY is not defined");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    let endpoint = "";
    if (ioc.type === "IPV4" || ioc.type === "IPV6") {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc.value)}`;
    } else if (ioc.type === "DOMAIN") {
      endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc.value)}`;
    } else if (ioc.type === "HASH_SHA256" || ioc.type === "HASH_MD5") {
      endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc.value)}`;
    } else {
      return {
        provider: "VirusTotal",
        reputation: "UNKNOWN",
        threatLevel: "UNKNOWN",
        confidence: 0,
        summary: `VirusTotal does not support automatic lookup for IOC type '${ioc.type}'.`,
        status: "UNAVAILABLE",
      };
    }

    try {
      const res = await fetch(endpoint, {
        headers: {
          "x-apikey": apiKey,
          Accept: "application/json",
        },
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new Error(`VirusTotal returned HTTP ${res.status}`);
      }

      const json = (await res.json()) as any;
      const stats = json?.data?.attributes?.last_analysis_stats || {};
      const malicious = Number(stats.malicious || 0);
      const suspicious = Number(stats.suspicious || 0);
      const totalEngines: number = Object.values(stats).reduce<number>((a, b) => a + Number(b || 0), 0) || 1;

      let reputation: EnrichmentResult["reputation"] = "BENIGN";
      let threatLevel: EnrichmentResult["threatLevel"] = "LOW";
      const confidence = Math.min(100, Math.round(((malicious * 2 + suspicious) / totalEngines) * 100));

      if (malicious >= 5) {
        reputation = "MALICIOUS";
        threatLevel = "CRITICAL";
      } else if (malicious >= 1 || suspicious >= 3) {
        reputation = "SUSPICIOUS";
        threatLevel = "HIGH";
      }

      return {
        provider: "VirusTotal",
        reputation,
        threatLevel,
        confidence,
        classification: json?.data?.attributes?.meaningful_name || "Telemetry Artifact",
        source: "VirusTotal v3 Live API",
        summary: `VirusTotal Analysis: ${malicious} engines flagged malicious, ${suspicious} suspicious out of ${totalEngines} total security engines.`,
        metadata: {
          stats,
          lastAnalysisDate: json?.data?.attributes?.last_analysis_date,
        },
        status: "ENRICHED",
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}

export const enrichmentService = new ThreatIntelEnrichmentService();
