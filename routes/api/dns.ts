import { define } from "../../utils.ts";

type RecordType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT" | "SOA" | "SRV";

interface GoogleDnsResponse {
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
  { subdomain: "@", types: ["A", "AAAA", "TXT", "MX", "NS", "SOA"] },
  { subdomain: "www", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "mail", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "ftp", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "smtp", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "pop", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "imap", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "webmail", types: ["A", "AAAA", "CNAME"] },
  { subdomain: "_dmarc", types: ["TXT"] },
  { subdomain: "autodiscover", types: ["CNAME", "A"] },
  { subdomain: "autoconfig", types: ["CNAME", "A"] },
  { subdomain: "lyncdiscover", types: ["CNAME", "A"] },
  { subdomain: "sip", types: ["CNAME", "A"] },
  { subdomain: "enterpriseregistration", types: ["CNAME"] },
  { subdomain: "enterpriseenrollment", types: ["CNAME"] },
  { subdomain: "_sipfederationtls._tcp", types: ["SRV"] },
  { subdomain: "_sip._tls", types: ["SRV"] },
  { subdomain: "_mta-sts", types: ["TXT"] },
  { subdomain: "_smtp._tls", types: ["TXT"] },
  { subdomain: "selector1._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "selector2._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "google._domainkey", types: ["TXT", "CNAME"] },
  { subdomain: "_dkim", types: ["TXT"] },
  { subdomain: "_domainkey", types: ["TXT"] },
];

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

async function detectWildcard(domain: string): Promise<WildcardInfo> {
  const testDomain = `_wildcard-test-${Date.now()}.${domain}`;
  const wildcardTargets = new Set<string>();
  let wildcardCname: string | null = null;

  try {
    const res = await fetch(`https://dns.google/resolve?name=${testDomain}&type=A`);
    const data: GoogleDnsResponse = await res.json();

    if (data.Status === 0 && data.Answer) {
      for (const a of data.Answer) {
        const value = a.data.replace(/\.$/, "");
        wildcardTargets.add(value);
        if (a.type === 5) wildcardCname = value; // CNAME in chain
      }
    }
  } catch {
    // Ignore errors
  }

  return { hasWildcard: wildcardTargets.size > 0, wildcardTargets, wildcardCname };
}

function isWildcardResult(
  record: DnsRecord,
  wildcard: WildcardInfo
): boolean {
  if (!wildcard.hasWildcard) return false;

  const value =
    typeof record.value === "string"
      ? record.value
      : "exchange" in record.value
        ? String((record.value as { exchange: string }).exchange)
        : "target" in record.value
          ? String((record.value as { target: string }).target)
          : null;

  if (!value) return false;

  return wildcard.wildcardTargets.has(value);
}

async function queryDns(
  domain: string,
  subdomain: string,
  type: RecordType
): Promise<QueryResult> {
  const fullDomain = subdomain === "@" ? domain : `${subdomain}.${domain}`;
  const typeNum = DNS_TYPE_MAP[type];

  try {
    const params = new URLSearchParams({
      name: fullDomain,
      type: typeNum.toString(),
    });
    const url = `https://dns.google/resolve?${params}`;

    const response = await fetch(url);
    if (!response.ok) {
      return {
        subdomain,
        type,
        records: [],
        error: `HTTP ${response.status}`,
      };
    }

    const data: GoogleDnsResponse = await response.json();

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

    return { subdomain, type, records };
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

    // Detect wildcard records in parallel with other queries
    const wildcardPromise = detectWildcard(cleanDomain);

    const queryPromises: Promise<QueryResult>[] = [];
    for (const query of QUERIES_TO_RUN) {
      for (const type of query.types) {
        queryPromises.push(queryDns(cleanDomain, query.subdomain, type));
      }
    }

    const [wildcard, ...results] = await Promise.all([
      wildcardPromise,
      ...queryPromises,
    ]);

    // Subdomains that should be filtered if they match wildcard
    const wildcardFilteredSubdomains = new Set([
      "www",
      "mail",
      "ftp",
      "smtp",
      "pop",
      "imap",
      "webmail",
      "autodiscover",
      "autoconfig",
      "lyncdiscover",
      "sip",
      "enterpriseregistration",
      "enterpriseenrollment",
      "selector1._domainkey",
      "selector2._domainkey",
      "google._domainkey",
    ]);

    // Flatten all records with subdomain as name
    const allRecords: Array<{ name: string; type: string; value: string | object; ttl: number }> = [];

    for (const result of results) {
      if (result.records.length === 0) continue;

      // Filter out wildcard matches for applicable subdomains
      let filteredRecords = result.records;
      if (wildcard.hasWildcard && wildcardFilteredSubdomains.has(result.subdomain)) {
        filteredRecords = result.records.filter((r) => !isWildcardResult(r, wildcard));
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

    return Response.json({
      success: true,
      domain: cleanDomain,
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
    });
  },
});
