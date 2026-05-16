export interface RecentWikiEntry {
  id: string;
  kind: "agent_finding" | "observed_violation" | "regression_test" | "safety_rule";
  title: string;
  summary: string;
  created_at: string;
  severity?: string | null;
  status?: string | null;
  matched_rule_id?: string | null;
  source_path: string;
  app_path: string;
}

export interface WikiSafetyRule {
  id: string;
  title: string;
  source: string;
  source_url?: string | null;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  rule_text: string;
  unsafe_patterns: string[];
  safe_patterns: string[];
  created_at: string;
}

const viteEnv = (import.meta as ImportMeta & { env?: { VITE_API_BASE_URL?: string } }).env;
const apiBaseUrl = (viteEnv?.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

function apiUrl(path: string) {
  return `${apiBaseUrl}${path}`;
}

async function fetchJson<T>(path: string): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 3500);

  try {
    const response = await fetch(apiUrl(path), {
      headers: { "Content-Type": "application/json" },
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }

    return (await response.json()) as T;
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function fetchRecentWikiEntries(limit = 25): Promise<RecentWikiEntry[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  const payload = await fetchJson<{ entries: RecentWikiEntry[] }>(`/wiki/recent?${params.toString()}`);
  return payload.entries;
}

export async function fetchWikiRules(): Promise<WikiSafetyRule[]> {
  const payload = await fetchJson<{ safety_rules: WikiSafetyRule[] }>("/wiki");
  return payload.safety_rules ?? [];
}
