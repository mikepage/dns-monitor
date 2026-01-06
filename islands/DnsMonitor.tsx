import { useSignal, signal } from "@preact/signals";
import { useEffect } from "preact/hooks";

const copiedId = signal<string | null>(null);

function CopyButton({ text, id }: { text: string; id: string }) {
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      copiedId.value = id;
      setTimeout(() => {
        if (copiedId.value === id) copiedId.value = null;
      }, 2000);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      copiedId.value = id;
      setTimeout(() => {
        if (copiedId.value === id) copiedId.value = null;
      }, 2000);
    }
  };

  const isCopied = copiedId.value === id;

  return (
    <button
      onClick={handleCopy}
      class="p-1 rounded hover:bg-[#f0f0f0] transition-colors shrink-0"
      title={isCopied ? "Copied!" : "Copy to clipboard"}
    >
      {isCopied ? (
        <svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
      ) : (
        <svg class="w-4 h-4 text-[#999] hover:text-[#666]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
    </button>
  );
}

interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  value: string | object;
}

const TYPE_COLORS: Record<string, { bg: string; text: string }> = {
  A: { bg: "bg-blue-100", text: "text-blue-700" },
  AAAA: { bg: "bg-indigo-100", text: "text-indigo-700" },
  CNAME: { bg: "bg-purple-100", text: "text-purple-700" },
  MX: { bg: "bg-orange-100", text: "text-orange-700" },
  TXT: { bg: "bg-green-100", text: "text-green-700" },
  NS: { bg: "bg-cyan-100", text: "text-cyan-700" },
  SOA: { bg: "bg-slate-200", text: "text-slate-700" },
  SRV: { bg: "bg-pink-100", text: "text-pink-700" },
};

interface WildcardInfo {
  detected: boolean;
  cname: string | null;
  targets: string[];
}

interface DnssecInfo {
  enabled: boolean;
  valid?: boolean;
}

interface DnsResult {
  domain: string;
  resolver: string;
  queryTime: number;
  totalRecords: number;
  records: DnsRecord[];
  wildcard?: WildcardInfo;
  dnssec?: DnssecInfo;
}

function parseHash(): string | null {
  const hash = window.location.hash;
  if (!hash || hash === "#") return null;
  return hash.slice(1);
}

function updateHash(domain: string) {
  if (domain) {
    window.history.replaceState(null, "", `#${domain}`);
  } else {
    window.history.replaceState(null, "", window.location.pathname);
  }
}

type Resolver = "google" | "cloudflare";

export default function DnsMonitor() {
  const domain = useSignal("");
  const resolver = useSignal<Resolver>("google");
  const dnssecValidation = useSignal(true);
  const isLoading = useSignal(false);
  const result = useSignal<DnsResult | null>(null);
  const error = useSignal<string | null>(null);
  const initialLoadDone = useSignal(false);

  const handleLookup = async () => {
    error.value = null;
    result.value = null;

    const domainValue = domain.value.trim();
    if (!domainValue) {
      error.value = "Please enter a domain name";
      return;
    }

    isLoading.value = true;

    try {
      const params = new URLSearchParams({
        domain: domainValue,
        resolver: resolver.value,
        ...(dnssecValidation.value && { dnssec: "true" }),
      });
      const response = await fetch(`/api/dns?${params}`);
      const data = await response.json();

      if (!data.success) {
        error.value = data.error || "DNS lookup failed";
        return;
      }

      result.value = data;
      updateHash(data.domain);
    } catch {
      error.value = "Failed to perform DNS lookup";
    } finally {
      isLoading.value = false;
    }
  };

  const handleClear = () => {
    domain.value = "";
    result.value = null;
    error.value = null;
    updateHash("");
  };

  useEffect(() => {
    const handleHashChange = () => {
      const hashDomain = parseHash();
      if (hashDomain && !initialLoadDone.value) {
        domain.value = hashDomain;
        initialLoadDone.value = true;
        handleLookup();
      } else {
        initialLoadDone.value = true;
      }
    };

    handleHashChange();

    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const formatValue = (value: string | object): string => {
    if (typeof value === "string") return value;
    if (typeof value === "object" && value !== null) {
      const obj = value as Record<string, unknown>;
      if ("preference" in obj && "exchange" in obj) {
        return `${obj.preference} ${obj.exchange}`;
      }
      if ("priority" in obj && "target" in obj) {
        return `${obj.priority} ${obj.weight} ${obj.port} ${obj.target}`;
      }
      if ("mname" in obj) {
        const soa = obj as {
          mname: string;
          rname: string;
          serial: number;
          refresh: number;
          retry: number;
          expire: number;
          minimum: number;
        };
        return `${soa.mname} ${soa.rname} ${soa.serial} ${soa.refresh} ${soa.retry} ${soa.expire} ${soa.minimum}`;
      }
      return JSON.stringify(value);
    }
    return String(value);
  };

  return (
    <div class="w-full">
      <div class="bg-white rounded-lg shadow p-6 mb-6">
        <div class="flex flex-col md:flex-row gap-3 mb-4">
          <div class="flex-1">
            <input
              type="text"
              value={domain.value}
              onInput={(e) => (domain.value = (e.target as HTMLInputElement).value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleLookup();
              }}
              placeholder="example.com"
              class="w-full px-4 py-3 border border-[#ddd] rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-sm bg-white"
            />
          </div>
          <div class="flex gap-2">
            <button
              onClick={handleLookup}
              disabled={!domain.value.trim() || isLoading.value}
              class="px-6 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm font-medium"
            >
              {isLoading.value ? "Scanning..." : "Scan DNS"}
            </button>
            {(result.value || error.value) && (
              <button
                onClick={handleClear}
                class="px-4 py-3 bg-[#f0f0f0] text-[#666] rounded-md hover:bg-[#e5e5e5] transition-colors text-sm"
              >
                Clear
              </button>
            )}
          </div>
        </div>
        <div class="flex flex-wrap items-center gap-4">
          <div class="flex items-center gap-2">
            <label class="text-xs text-[#666]">Resolver</label>
            <select
              value={resolver.value}
              onChange={(e) => (resolver.value = (e.target as HTMLSelectElement).value as Resolver)}
              class="px-3 py-1.5 border border-[#ddd] rounded-md text-sm bg-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="google">Google</option>
              <option value="cloudflare">Cloudflare</option>
            </select>
          </div>
          <div class="flex items-center gap-2">
            <label class="text-xs text-[#666]">DNSSEC</label>
            <div class="flex rounded-md overflow-hidden border border-[#ddd]">
              <label class={`px-3 py-1.5 text-xs cursor-pointer transition-colors ${!dnssecValidation.value ? "bg-blue-600 text-white" : "bg-white text-[#666] hover:bg-[#f5f5f5]"}`}>
                <input
                  type="radio"
                  name="dnssec"
                  checked={!dnssecValidation.value}
                  onChange={() => (dnssecValidation.value = false)}
                  class="sr-only"
                />
                Off
              </label>
              <label class={`px-3 py-1.5 text-xs cursor-pointer transition-colors border-l border-[#ddd] ${dnssecValidation.value ? "bg-blue-600 text-white" : "bg-white text-[#666] hover:bg-[#f5f5f5]"}`}>
                <input
                  type="radio"
                  name="dnssec"
                  checked={dnssecValidation.value}
                  onChange={() => (dnssecValidation.value = true)}
                  class="sr-only"
                />
                On
              </label>
            </div>
          </div>
        </div>
      </div>

      {error.value && (
        <div class="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <p class="text-red-600 text-sm">{error.value}</p>
        </div>
      )}

      {isLoading.value && (
        <div class="bg-white rounded-lg shadow p-6 mb-6">
          <div class="flex items-center gap-3">
            <div class="w-5 h-5 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
            <span class="text-sm text-[#666]">Scanning DNS records for {domain.value}...</span>
          </div>
        </div>
      )}

      {result.value && (
        <>
          <div class="bg-white rounded-lg shadow p-6 mb-6">
            <div class="flex flex-wrap items-center gap-4">
              <div>
                <span class="text-xs text-[#999] block">Domain</span>
                <span class="text-sm text-[#111]">{result.value.domain}</span>
              </div>
              <div>
                <span class="text-xs text-[#999] block">Resolver</span>
                <span class="text-sm text-[#111] capitalize">{result.value.resolver}</span>
              </div>
              <div>
                <span class="text-xs text-[#999] block">Records Found</span>
                <span class="text-sm text-[#111]">{result.value.totalRecords}</span>
              </div>
              <div>
                <span class="text-xs text-[#999] block">Query Time</span>
                <span class="text-sm text-[#111]">{result.value.queryTime}ms</span>
              </div>
              {result.value.dnssec && (
                <div>
                  <span class="text-xs text-[#999] block">DNSSEC</span>
                  <span class={`text-sm ${result.value.dnssec.valid ? "text-green-600" : "text-[#999]"}`}>
                    {result.value.dnssec.valid ? "Valid" : "Not validated"}
                  </span>
                </div>
              )}
            </div>
          </div>

          {result.value.wildcard && (
            <div class="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-6">
              <div class="flex items-start gap-3">
                <svg class="w-5 h-5 text-amber-600 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <p class="text-sm font-medium text-amber-800">Wildcard DNS detected</p>
                  <p class="text-xs text-amber-700 mt-1">
                    This domain has a wildcard record (*.{result.value.domain})
                    {result.value.wildcard.cname && (
                      <span>
                        {" "}pointing to <code class="bg-amber-100 px-1 rounded">{result.value.wildcard.cname}</code>
                      </span>
                    )}
                    . False positive subdomain records have been filtered out.
                  </p>
                </div>
              </div>
            </div>
          )}

          {(() => {
            const mainRecords = result.value.records.filter((r) => r.type !== "NS" && r.type !== "SOA");
            const nssoaRecords = result.value.records.filter((r) => r.type === "NS" || r.type === "SOA");

            return (
              <>
                {mainRecords.length > 0 ? (
                  <div class="bg-white rounded-lg shadow overflow-hidden">
                    <table class="w-full text-sm">
                      <thead>
                        <tr class="border-b border-[#eee] bg-[#fafafa]">
                          <th class="text-left px-4 py-3 text-xs font-medium text-[#666] uppercase tracking-wider">Name</th>
                          <th class="text-left px-4 py-3 text-xs font-medium text-[#666] uppercase tracking-wider">Type</th>
                          <th class="text-left px-4 py-3 text-xs font-medium text-[#666] uppercase tracking-wider">Value</th>
                          <th class="text-right px-4 py-3 text-xs font-medium text-[#666] uppercase tracking-wider">TTL</th>
                        </tr>
                      </thead>
                      <tbody class="divide-y divide-[#eee]">
                        {mainRecords.map((record, idx) => {
                          const formattedValue = formatValue(record.value);
                          return (
                            <tr key={idx} class="hover:bg-[#fafafa]">
                              <td class="px-4 py-3 text-[#111]">{record.name}</td>
                              <td class="px-4 py-3">
                                <span class={`text-xs px-2 py-0.5 rounded ${TYPE_COLORS[record.type]?.bg ?? "bg-[#e5e5e5]"} ${TYPE_COLORS[record.type]?.text ?? "text-[#666]"}`}>{record.type}</span>
                              </td>
                              <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                  <code class="text-[#111] break-all flex-1">{formattedValue}</code>
                                  <CopyButton text={formattedValue} id={`record-${idx}`} />
                                </div>
                              </td>
                              <td class="px-4 py-3 text-right text-[#999]">{record.ttl}s</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div class="bg-white rounded-lg shadow p-6">
                    <p class="text-sm text-[#666]">No DNS records found for this domain.</p>
                  </div>
                )}

                {nssoaRecords.length > 0 && (
                  <div class="bg-white rounded-lg shadow overflow-hidden mt-6">
                    <div class="px-4 py-3 bg-[#fafafa] border-b border-[#eee]">
                      <h3 class="text-xs font-medium text-[#666] uppercase tracking-wider">NS / SOA Records</h3>
                    </div>
                    <table class="w-full text-sm">
                      <thead>
                        <tr class="border-b border-[#eee] bg-[#fafafa]">
                          <th class="text-left px-4 py-3 text-xs font-medium text-[#666] uppercase tracking-wider">Name</th>
                          <th class="text-left px-4 py-3 text-xs font-medium text-[#666] uppercase tracking-wider">Type</th>
                          <th class="text-left px-4 py-3 text-xs font-medium text-[#666] uppercase tracking-wider">Value</th>
                          <th class="text-right px-4 py-3 text-xs font-medium text-[#666] uppercase tracking-wider">TTL</th>
                        </tr>
                      </thead>
                      <tbody class="divide-y divide-[#eee]">
                        {nssoaRecords.map((record, idx) => {
                          const formattedValue = formatValue(record.value);
                          return (
                            <tr key={idx} class="hover:bg-[#fafafa]">
                              <td class="px-4 py-3 text-[#111]">{record.name}</td>
                              <td class="px-4 py-3">
                                <span class={`text-xs px-2 py-0.5 rounded ${TYPE_COLORS[record.type]?.bg ?? "bg-[#e5e5e5]"} ${TYPE_COLORS[record.type]?.text ?? "text-[#666]"}`}>{record.type}</span>
                              </td>
                              <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                  <code class="text-[#111] break-all flex-1">{formattedValue}</code>
                                  <CopyButton text={formattedValue} id={`nssoa-${idx}`} />
                                </div>
                              </td>
                              <td class="px-4 py-3 text-right text-[#999]">{record.ttl}s</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            );
          })()}
        </>
      )}
    </div>
  );
}
