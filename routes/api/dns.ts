/// <reference lib="deno.unstable" />
import { define } from "../../utils.ts";

type RecordType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT" | "SOA" | "SRV";
type Resolver = "google" | "cloudflare";

interface CrtShEntry {
  name_value: string;
  not_after: string;
}

interface DnsApiResponse {
  Status: number;
  AD?: boolean;
  CD?: boolean;
  Answer?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
}

const RESOLVER_URLS: Record<Resolver, string> = {
  google: "https://dns.google/resolve",
  cloudflare: "https://cloudflare-dns.com/dns-query",
};

const DNS_TYPE_MAP: Record<string, number> = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  MX: 15,
  NS: 2,
  TXT: 16,
  SOA: 6,
  SRV: 33,
};

interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  value: string | object;
}

interface QueryResult {
  subdomain: string;
  type: string;
  records: DnsRecord[];
  error?: string;
}

interface WildcardInfo {
  hasWildcard: boolean;
  wildcardTargets: Set<string>;
  wildcardCname: string | null;
}

const QUERIES_TO_RUN: Array<{ subdomain: string; types: RecordType[] }> = [
  // Root domain
  { subdomain: "@", types: ["A", "AAAA", "TXT", "MX", "SOA"] },

  // Nameservers
  { subdomain: "@", types: ["NS"] },

  // Common subdomains
  { subdomain: "www", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "mail", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "ftp", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "smtp", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "pop", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "imap", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "webmail", types: ["A", "AAAA", "CNAME"] },

  // Email authentication
  { subdomain: "_dmarc", types: ["TXT"] },
  { subdomain: "_mta-sts", types: ["TXT"] },
  { subdomain: "_smtp._tls", types: ["TXT"] },

  // Microsoft 365
  { subdomain: "autodiscover", types: ["CNAME", "A"] },
  { subdomain: "lyncdiscover", types: ["CNAME", "A"] },
  { subdomain: "sip", types: ["CNAME", "A"] },
  { subdomain: "enterpriseregistration", types: ["CNAME"] },
  { subdomain: "enterpriseenrollment", types: ["CNAME"] },
  { subdomain: "_sipfederationtls._tcp", types: ["SRV"] },
  { subdomain: "_sip._tls", types: ["SRV"] },

  // Other providers
  { subdomain: "autoconfig", types: ["CNAME", "A"] },

  // DKIM selectors
  { subdomain: "selector1._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "selector2._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "google._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "s1._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "s2._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "k2._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "k3._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "default._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "transip-a._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "transip-b._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "transip-c._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "x-transip-mail-auth", types: ["TXT", "CNAME"] },
  { subdomain: "_dkim", types: ["TXT"] },
  { subdomain: "_domainkey", types: ["TXT"] },
];

// Subdomains that should be filtered when matching wildcard DNS
// Excludes root (@) and underscore-prefixed records (technical DNS records)
const WILDCARD_FILTERED_SUBDOMAINS = QUERIES_TO_RUN
  .map((q) => q.subdomain)
  .filter((s) => s !== "@" && !s.startsWith("_"));

function parseRecord(
  answer: { name: string; type: number; TTL: number; data: string },
  type: RecordType
): DnsRecord {
  let value: string | object = answer.data;

  switch (type) {
    case "MX": {
      const parts = answer.data.split(" ");
      value = {
        preference: parseInt(parts[0], 10),
        exchange: parts.slice(1).join(" ").replace(/\.$/, ""),
      };
      break;
    }
    case "SOA": {
      const parts = answer.data.split(" ");
      value = {
        mname: parts[0]?.replace(/\.$/, "") || "",
        rname: parts[1]?.replace(/\.$/, "") || "",
        serial: parseInt(parts[2], 10) || 0,
        refresh: parseInt(parts[3], 10) || 0,
        retry: parseInt(parts[4], 10) || 0,
        expire: parseInt(parts[5], 10) || 0,
        minimum: parseInt(parts[6], 10) || 0,
      };
      break;
    }
    case "SRV": {
      const parts = answer.data.split(" ");
      value = {
        priority: parseInt(parts[0], 10) || 0,
        weight: parseInt(parts[1], 10) || 0,
        port: parseInt(parts[2], 10) || 0,
        target: parts[3]?.replace(/\.$/, "") || "",
      };
      break;
    }
    case "TXT":
      value = answer.data.replace(/^"|"$/g, "");
      break;
    case "CNAME":
    case "NS":
      value = answer.data.replace(/\.$/, "");
      break;
  }

  return {
    name: answer.name.replace(/\.$/, ""),
    type,
    ttl: answer.TTL,
    value,
  };
}

async function detectWildcard(domain: string, resolver: Resolver): Promise<WildcardInfo> {
  const testDomain = `_wildcard-test-${Date.now()}.${domain}`;
  const wildcardTargets = new Set<string>();
  let wildcardCname: string | null = null;

  const baseUrl = RESOLVER_URLS[resolver];
  const headers: Record<string, string> = resolver === "cloudflare" ? { Accept: "application/dns-json" } : {};

  // Query A, AAAA, TXT, CAA in parallel to detect all wildcard records
  const typesToCheck = ["A", "AAAA", "TXT", "CAA"];

  try {
    const responses = await Promise.all(
      typesToCheck.map((type) =>
        fetch(`${baseUrl}?name=${testDomain}&type=${type}`, { headers })
          .then((res) => res.json())
          .catch(() => null)
      )
    );

    for (const data of responses) {
      if (data?.Status === 0 && data?.Answer) {
        for (const a of data.Answer) {
          const value = a.data.replace(/\.$/, "").replace(/^"|"$/g, "");
          wildcardTargets.add(value);
          if (a.type === 5) wildcardCname = value; // CNAME in chain
        }
      }
    }
  } catch {
    // Ignore errors
  }

  return { hasWildcard: wildcardTargets.size > 0, wildcardTargets, wildcardCname };
}

// Record types affected by wildcard records
const WILDCARD_AFFECTED_TYPES = new Set(["A", "AAAA", "CNAME", "TXT", "CAA"]);

// Deno KV for caching CT results (works in Deno Deploy)
let kv: Deno.Kv | null = null;
async function getKv(): Promise<Deno.Kv | null> {
  if (kv) return kv;
  try {
    kv = await Deno.openKv();
    return kv;
  } catch {
    return null;
  }
}

const CT_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

interface CtCacheEntry {
  subdomains: string[];
  totalCerts: number;
  activeCerts: number;
  cachedAt: number;
}

// Fetch subdomains from Certificate Transparency logs (with caching)
async function fetchCtSubdomains(domain: string): Promise<{ subdomains: string[]; totalCerts: number; activeCerts: number; cached?: boolean }> {
  const cacheKey = ["ct", domain];

  // Try to get from cache
  try {
    const store = await getKv();
    if (store) {
      const cached = await store.get<CtCacheEntry>(cacheKey);
      if (cached.value && Date.now() - cached.value.cachedAt < CT_CACHE_TTL_MS) {
        return {
          subdomains: cached.value.subdomains,
          totalCerts: cached.value.totalCerts,
          activeCerts: cached.value.activeCerts,
          cached: true,
        };
      }
    }
  } catch {
    // Cache read failed, continue to fetch
  }

  try {
    const crtUrl = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const response = await fetch(crtUrl, {
      headers: { "User-Agent": "DNS-Monitor/1.0" },
    });

    if (!response.ok) {
      return { subdomains: [], totalCerts: 0, activeCerts: 0 };
    }

    const text = await response.text();
    if (!text || text.trim() === "") {
      return { subdomains: [], totalCerts: 0, activeCerts: 0 };
    }

    const entries: CrtShEntry[] = JSON.parse(text);
    const now = new Date();

    // Filter to only include certificates that haven't expired
    const activeCerts = entries.filter((entry) => new Date(entry.not_after) > now);

    // Extract unique subdomains (exclude wildcards and root domain)
    const subdomainSet = new Set<string>();
    for (const entry of activeCerts) {
      const names = entry.name_value.split("\n").map((n) => n.trim().toLowerCase());
      for (const name of names) {
        // Skip wildcards, root domain, and invalid entries
        if (!name || name.startsWith("*") || name === domain || !name.endsWith(`.${domain}`)) {
          continue;
        }
        // Extract subdomain part (remove the .domain suffix)
        const subdomain = name.slice(0, -(domain.length + 1));
        if (subdomain && !subdomain.includes("@") && !subdomain.includes(" ")) {
          subdomainSet.add(subdomain);
        }
      }
    }

    const result = {
      subdomains: Array.from(subdomainSet),
      totalCerts: entries.length,
      activeCerts: activeCerts.length,
    };

    // Store in cache
    try {
      const store = await getKv();
      if (store) {
        await store.set(cacheKey, { ...result, cachedAt: Date.now() } as CtCacheEntry);
      }
    } catch {
      // Cache write failed, ignore
    }

    return result;
  } catch {
    return { subdomains: [], totalCerts: 0, activeCerts: 0 };
  }
}

async function queryDns(
  domain: string,
  subdomain: string,
  type: RecordType,
  resolver: Resolver,
  requestDnssec: boolean
): Promise<QueryResult & { dnssecValid?: boolean }> {
  const fullDomain = subdomain === "@" ? domain : `${subdomain}.${domain}`;
  const typeNum = DNS_TYPE_MAP[type];

  try {
    const baseUrl = RESOLVER_URLS[resolver];
    const params = new URLSearchParams({
      name: fullDomain,
      type: typeNum.toString(),
      ...(requestDnssec && { do: "true" }), // Request DNSSEC OK bit
    });
    const url = `${baseUrl}?${params}`;
    const headers: Record<string, string> = resolver === "cloudflare" ? { Accept: "application/dns-json" } : {};

    const response = await fetch(url, { headers });
    if (!response.ok) {
      return {
        subdomain,
        type,
        records: [],
        error: `HTTP ${response.status}`,
      };
    }

    const data: DnsApiResponse = await response.json();

    if (data.Status !== 0) {
      if (data.Status === 3) {
        return { subdomain, type, records: [] };
      }
      return {
        subdomain,
        type,
        records: [],
        error: `DNS error: ${data.Status}`,
      };
    }

    if (!data.Answer) {
      return { subdomain, type, records: [] };
    }

    const records = data.Answer.filter((a) => a.type === typeNum).map((a) =>
      parseRecord(a, type)
    );

    return { subdomain, type, records, dnssecValid: data.AD };
  } catch (err) {
    return {
      subdomain,
      type,
      records: [],
      error: err instanceof Error ? err.message : "Query failed",
    };
  }
}

export const handler = define.handlers({
  async GET(ctx) {
    const url = new URL(ctx.req.url);
    const domain = url.searchParams.get("domain");
    const resolverParam = url.searchParams.get("resolver") || "google";
    const dnssecParam = url.searchParams.get("dnssec") === "true";
    const ctParam = url.searchParams.get("ct") === "true";

    const resolver: Resolver = resolverParam === "cloudflare" ? "cloudflare" : "google";

    if (!domain) {
      return Response.json(
        { success: false, error: "Domain is required" },
        { status: 400 }
      );
    }

    const cleanDomain = domain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "");

    const startTime = performance.now();

    // Fetch CT subdomains first if enabled (need results before DNS queries)
    let ctData: { subdomains: string[]; totalCerts: number; activeCerts: number; cached?: boolean } | null = null;
    if (ctParam) {
      ctData = await fetchCtSubdomains(cleanDomain);
    }

    // Build query list: static queries + CT-discovered subdomains
    const queriesToRun = [...QUERIES_TO_RUN];

    // Add CT-discovered subdomains (query A, AAAA, CNAME for each)
    const staticSubdomains = new Set(QUERIES_TO_RUN.map((q) => q.subdomain));
    const ctSubdomains: string[] = [];
    if (ctData) {
      for (const subdomain of ctData.subdomains) {
        if (!staticSubdomains.has(subdomain)) {
          queriesToRun.push({ subdomain, types: ["A", "AAAA", "CNAME"] });
          ctSubdomains.push(subdomain);
        }
      }
    }

    // Detect wildcard records in parallel with other queries
    const wildcardPromise = detectWildcard(cleanDomain, resolver);

    const queryPromises: Promise<QueryResult & { dnssecValid?: boolean }>[] = [];
    for (const query of queriesToRun) {
      for (const type of query.types) {
        queryPromises.push(queryDns(cleanDomain, query.subdomain, type, resolver, dnssecParam));
      }
    }

    const [wildcard, ...results] = await Promise.all([
      wildcardPromise,
      ...queryPromises,
    ]);

    // Subdomains that should be filtered if they match wildcard
    const wildcardFilteredSubdomains = new Set([
      ...WILDCARD_FILTERED_SUBDOMAINS,
      // Add CT-discovered subdomains to wildcard filter
      ...ctSubdomains,
    ]);

    // Find subdomains that have CNAME records (to skip A/AAAA for those)
    const subdomainsWithCname = new Set<string>();
    for (const result of results) {
      if (result.records.some((r) => r.type === "CNAME")) {
        subdomainsWithCname.add(result.subdomain);
      }
    }

    // Flatten all records with subdomain as name
    const allRecords: Array<{ name: string; type: string; value: string | object; ttl: number }> = [];

    for (const result of results) {
      if (result.records.length === 0) continue;

      // Filter out records that match wildcard targets (false positives)
      let filteredRecords = result.records;
      if (wildcard.hasWildcard && wildcardFilteredSubdomains.has(result.subdomain)) {
        filteredRecords = result.records.filter((r) => {
          if (!WILDCARD_AFFECTED_TYPES.has(r.type)) return true;
          // Check if record value matches wildcard targets
          const value = typeof r.value === "string" ? r.value : "";
          return !wildcard.wildcardTargets.has(value);
        });
      }

      // If subdomain has CNAME, only keep the CNAME record (per DNS standards, no other records should coexist)
      if (subdomainsWithCname.has(result.subdomain)) {
        filteredRecords = filteredRecords.filter((r) => r.type === "CNAME");
      }

      for (const record of filteredRecords) {
        allRecords.push({
          name: result.subdomain,
          type: record.type,
          value: record.value,
          ttl: record.ttl,
        });
      }
    }

    // Sort: @ first, then alphabetically by name, then by type
    allRecords.sort((a, b) => {
      if (a.name === "@" && b.name !== "@") return -1;
      if (a.name !== "@" && b.name === "@") return 1;
      if (a.name !== b.name) return a.name.localeCompare(b.name);
      return a.type.localeCompare(b.type);
    });

    const endTime = performance.now();
    const queryTime = Math.round(endTime - startTime);

    // Check if any result has DNSSEC validated (AD flag)
    const dnssecValid = dnssecParam && results.some((r) => r.dnssecValid === true);

    return Response.json({
      success: true,
      domain: cleanDomain,
      resolver,
      queryTime,
      records: allRecords,
      totalRecords: allRecords.length,
      ...(wildcard.hasWildcard && {
        wildcard: {
          detected: true,
          cname: wildcard.wildcardCname,
          targets: Array.from(wildcard.wildcardTargets),
        },
      }),
      ...(dnssecParam && {
        dnssec: {
          enabled: true,
          valid: dnssecValid,
        },
      }),
      ...(ctData && {
        ct: {
          enabled: true,
          totalCerts: ctData.totalCerts,
          activeCerts: ctData.activeCerts,
          discoveredSubdomains: ctSubdomains.length,
          cached: ctData.cached || false,
        },
      }),
    });
  },
});
