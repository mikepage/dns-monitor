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
      // Fallback for older browsers
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
        <svg
          class="w-4 h-4 text-green-600"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M5 13l4 4L19 7"
          />
        </svg>
      ) : (
        <svg
          class="w-4 h-4 text-[#999] hover:text-[#666]"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
          />
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

interface RecordGroup {
  subdomain: string;
  type: string;
  records: DnsRecord[];
}

interface WildcardInfo {
  detected: boolean;
  cname: string | null;
  targets: string[];
}

interface DnsResult {
  domain: string;
  queryTime: number;
  totalRecords: number;
  categories: {
    root: RecordGroup[];
    common: RecordGroup[];
    mail: RecordGroup[];
    microsoft: RecordGroup[];
    security: RecordGroup[];
  };
  wildcard?: WildcardInfo;
}

const CATEGORY_LABELS: Record<string, { title: string; description: string }> =
  {
    root: { title: "Root Domain (@)", description: "Primary domain records" },
    common: { title: "Common Subdomains", description: "www, ftp, etc." },
    mail: {
      title: "Email Configuration",
      description: "Mail servers, SPF, DKIM, DMARC",
    },
    microsoft: {
      title: "Microsoft 365",
      description: "Autodiscover, Teams, Skype for Business",
    },
    security: {
      title: "Security & Standards",
      description: "MTA-STS, TLS reporting, autoconfig",
    },
  };

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

export default function DnsMonitor() {
  const domain = useSignal("");
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
      const params = new URLSearchParams({ domain: domainValue });
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

  const renderCategory = (
    categoryKey: string,
    groups: RecordGroup[]
  ): preact.JSX.Element | null => {
    if (groups.length === 0) return null;

    const label = CATEGORY_LABELS[categoryKey];

    return (
      <div class="bg-white rounded-lg shadow p-6 mb-4">
        <h3 class="text-base font-medium text-[#111] mb-1">{label.title}</h3>
        <p class="text-xs text-[#999] mb-4">{label.description}</p>

        <div class="space-y-3">
          {groups.map((group, idx) => (
            <div key={idx} class="border border-[#eee] rounded-md">
              <div class="px-3 py-2 bg-[#fafafa] border-b border-[#eee] flex items-center gap-2">
                <span class="text-sm text-[#666]">
                  {group.subdomain === "@" ? "(root)" : group.subdomain}
                </span>
                <span class="text-xs px-2 py-0.5 bg-[#e5e5e5] rounded text-[#666]">
                  {group.type}
                </span>
              </div>
              <div class="divide-y divide-[#eee]">
                {group.records.map((record, ridx) => {
                  const formattedValue = formatValue(record.value);
                  const copyId = `${categoryKey}-${idx}-${ridx}`;
                  return (
                    <div key={ridx} class="px-3 py-2 flex items-center gap-2">
                      <code class="text-sm text-[#111] break-all flex-1">
                        {formattedValue}
                      </code>
                      <CopyButton text={formattedValue} id={copyId} />
                      <span class="text-xs text-[#999] shrink-0">
                        TTL: {record.ttl}s
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div class="w-full">
      <div class="bg-white rounded-lg shadow p-6 mb-6">
        <div class="flex flex-col md:flex-row gap-3">
          <div class="flex-1">
            <input
              type="text"
              value={domain.value}
              onInput={(e) =>
                (domain.value = (e.target as HTMLInputElement).value)
              }
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
            <span class="text-sm text-[#666]">
              Scanning DNS records for {domain.value}...
            </span>
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
                <span class="text-xs text-[#999] block">Records Found</span>
                <span class="text-sm text-[#111]">
                  {result.value.totalRecords}
                </span>
              </div>
              <div>
                <span class="text-xs text-[#999] block">Query Time</span>
                <span class="text-sm text-[#111]">
                  {result.value.queryTime}ms
                </span>
              </div>
            </div>
          </div>

          {result.value.wildcard && (
            <div class="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-6">
              <div class="flex items-start gap-3">
                <svg
                  class="w-5 h-5 text-amber-600 shrink-0 mt-0.5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                  />
                </svg>
                <div>
                  <p class="text-sm font-medium text-amber-800">
                    Wildcard DNS detected
                  </p>
                  <p class="text-xs text-amber-700 mt-1">
                    This domain has a wildcard record (*.{result.value.domain})
                    {result.value.wildcard.cname && (
                      <span>
                        {" "}pointing to{" "}
                        <code class="bg-amber-100 px-1 rounded">
                          {result.value.wildcard.cname}
                        </code>
                      </span>
                    )}
                    . False positive subdomain records have been filtered out.
                  </p>
                </div>
              </div>
            </div>
          )}

          {renderCategory("root", result.value.categories.root)}
          {renderCategory("common", result.value.categories.common)}
          {renderCategory("mail", result.value.categories.mail)}
          {renderCategory("microsoft", result.value.categories.microsoft)}
          {renderCategory("security", result.value.categories.security)}

          {result.value.totalRecords === 0 && (
            <div class="bg-white rounded-lg shadow p-6">
              <p class="text-sm text-[#666]">
                No DNS records found for this domain.
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
