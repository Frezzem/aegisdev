import { findTyposquat } from "./popular.js";
import { assessPackage, DEFAULT_POLICY, matchesPackageList } from "./risk.js";
import type {
  Ecosystem,
  PackageFacts,
  PackageRef,
  PackageReport,
  Severity,
  SourceError,
  SourceStatus,
  VulnerabilityInfo,
} from "./types.js";

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface IntelOptions {
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  githubToken?: string;
  npmRegistry?: string;
  pypiRegistry?: string;
  policy?: Partial<typeof DEFAULT_POLICY>;
  now?: Date;
}

interface FetchJsonResult {
  ok: boolean;
  status: number;
  data?: unknown;
  error?: string;
  url: string;
  durationMs: number;
}

interface Collected {
  facts: PackageFacts;
  sources: SourceStatus[];
}

const PRIVACY_NOTE =
  "Aegis 仅向 NPM / PyPI / pypistats / OSV / GitHub 发送包名与版本等公开元数据，绝不上传源码、文件内容或密钥。";
const USER_AGENT = "AegisDev-VSCode/1.0.0";

export async function verifyPackage(
  ref: PackageRef,
  options: IntelOptions = {},
): Promise<PackageReport> {
  const started = Date.now();
  const policy = { ...DEFAULT_POLICY, ...options.policy };
  const registryUrl =
    ref.ecosystem === "npm"
      ? `${trimSlash(options.npmRegistry ?? "https://registry.npmjs.org")}/${encodePackagePath(ref.name)}`
      : `${trimSlash(options.pypiRegistry ?? "https://pypi.org/pypi")}/${encodeURIComponent(ref.name)}/json`;

  if (matchesPackageList(ref.name, policy.blocklist) || matchesPackageList(ref.name, policy.allowlist)) {
    const facts = emptyFacts(ref, registryUrl, false);
    facts.lookupState = "ok";
    facts.found = true;
    const assessment = assessPackage(facts, policy);
    return {
      kind: "package",
      ref,
      facts,
      assessment,
      sources: [
        {
          name: "团队策略",
          status: "ok",
          detail: assessment.blockedByPolicy ? "命中阻断名单" : "命中企业白名单",
        },
      ],
      generatedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      privacy: PRIVACY_NOTE,
    };
  }

  const { facts, sources } = await collectPackageFacts(ref, options);
  const assessment = assessPackage(facts, policy);
  return {
    kind: "package",
    ref,
    facts,
    assessment,
    sources,
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    privacy: PRIVACY_NOTE,
  };
}

export async function collectPackageFacts(
  ref: PackageRef,
  options: IntelOptions = {},
): Promise<Collected> {
  const timeoutMs = clampTimeout(options.timeoutMs ?? 2000);
  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as FetchLike);
  const now = options.now ?? new Date();
  const sources: SourceStatus[] = [];
  const sourceErrors: SourceError[] = [];

  if (!fetchImpl) {
    return {
      facts: {
        ...emptyFacts(ref, "", true),
        lookupState: "error",
        lookupError: "当前运行环境不支持 fetch",
      },
      sources: [{ name: "运行时", status: "error", detail: "缺少 fetch 实现" }],
    };
  }

  if (ref.ecosystem === "npm") {
    return collectNpm(ref, { ...options, timeoutMs, fetchImpl, now }, sources, sourceErrors);
  }
  return collectPypi(ref, { ...options, timeoutMs, fetchImpl, now }, sources, sourceErrors);
}

async function collectNpm(
  ref: PackageRef,
  options: Required<Pick<IntelOptions, "timeoutMs" | "now">> &
    IntelOptions & { fetchImpl: FetchLike },
  sources: SourceStatus[],
  sourceErrors: SourceError[],
): Promise<Collected> {
  const deadline = Date.now() + options.timeoutMs;
  const registryBase = trimSlash(options.npmRegistry ?? "https://registry.npmjs.org");
  const packagePath = encodePackagePath(ref.name);
  const registryUrl = `${registryBase}/${packagePath}`;
  const downloadsUrl = `https://api.npmjs.org/downloads/point/last-week/${packagePath}`;

  const [registry, downloads] = await Promise.all([
    fetchJson(options.fetchImpl, registryUrl, { headers: { Accept: "application/json" } }, options.timeoutMs),
    fetchJson(options.fetchImpl, downloadsUrl, { headers: { Accept: "application/json" } }, options.timeoutMs),
  ]);

  const facts = emptyFacts(ref, registryUrl, false);
  facts.sourceErrors = sourceErrors;

  if (!registry.ok && registry.status === 404) {
    facts.lookupState = "not-found";
    facts.found = false;
    sources.push({ name: "NPM Registry", status: "ok", detail: "404 · 未收录", url: registryUrl });
    sources.push({
      name: "NPM Downloads",
      status: downloads.ok ? "ok" : "degraded",
      detail: downloads.ok ? "last-week" : downloads.error,
      url: downloadsUrl,
    });
    for (const error of [downloads].filter((r) => !r.ok)) {
      sourceErrors.push({ source: "NPM Downloads", message: error.error ?? "请求失败" });
    }
    return { facts, sources };
  }

  if (!registry.ok) {
    facts.lookupState = "error";
    facts.lookupError = registry.error ?? `NPM Registry HTTP ${registry.status}`;
    sources.push({
      name: "NPM Registry",
      status: "error",
      detail: facts.lookupError,
      url: registryUrl,
    });
    return { facts, sources };
  }

  const data = asRecord(registry.data);
  const time = asRecord(data.time);
  const distTags = asRecord(data["dist-tags"]);
  const versions = asRecord(data.versions);
  const latest = asString(distTags.latest) ?? firstKey(versions);
  const requestedExact = ref.exactVersion ? ref.versionSpec : undefined;
  const resolved = requestedExact && versions[requestedExact] ? requestedExact : latest;
  const latestData = resolved ? asRecord(versions[resolved]) : {};
  const versionCount = Object.keys(versions).length;

  if (!resolved || versionCount === 0) {
    facts.lookupState = "error";
    facts.lookupError = "registry 返回了无法解析的包元数据";
    sources.push({
      name: "NPM Registry",
      status: "error",
      detail: facts.lookupError,
      url: registryUrl,
    });
    return { facts, sources };
  }

  facts.found = true;
  facts.lookupState = "ok";
  facts.version = resolved;
  facts.requestedVersionMissing = Boolean(requestedExact && !versions[requestedExact]);
  facts.description = asString(latestData.description) ?? asString(data.description);
  facts.homepage = asString(latestData.homepage) ?? asString(data.homepage);
  facts.repositoryUrl = extractRepository(
    latestData.repository ?? data.repository,
    asString(latestData.homepage),
  );
  facts.license = normalizeLicense(latestData.license ?? data.license);
  facts.deprecated = Boolean(latestData.deprecated);
  facts.hasInstallScript = latestData.hasInstallScript === true;
  facts.maintainers = Array.isArray(data.maintainers) ? data.maintainers.length : undefined;
  facts.latestVersionCount = versionCount;
  facts.createdAt = asString(time.created);
  facts.latestPublishedAt = resolved ? asString(time[resolved]) : undefined;

  if (facts.createdAt) {
    facts.ageDays = daysBetween(facts.createdAt, options.now);
  } else {
    facts.createdAt = earliestTime(time);
    if (facts.createdAt) {
      facts.ageDays = daysBetween(facts.createdAt, options.now);
    }
  }

  if (downloads.ok) {
    const downloadsData = asRecord(downloads.data);
    const value = asNumber(downloadsData.downloads);
    if (value !== undefined) {
      facts.weeklyDownloads = value;
      facts.downloadsSource = "NPM Downloads API（周）";
    }
  } else {
    sourceErrors.push({ source: "NPM Downloads", message: downloads.error ?? "请求失败" });
  }

  sources.push({
    name: "NPM Registry",
    status: "ok",
    detail: `${versionCount} 个版本`,
    url: registryUrl,
  });
  sources.push({
    name: "NPM Downloads",
    status: downloads.ok ? "ok" : "degraded",
    detail: downloads.ok ? "last-week" : downloads.error,
    url: downloadsUrl,
  });

  const remaining = Math.max(200, deadline - Date.now());
  const [osv, github] = await Promise.all([
    queryOsv(options.fetchImpl, ref.name, "npm", resolved, remaining),
    queryGitHub(options.fetchImpl, facts.repositoryUrl, options.githubToken, remaining),
  ]);

  if (osv.ok) {
    facts.vulnerabilities = mapOsvVulns(osv.data);
    sources.push({
      name: "OSV.dev",
      status: "ok",
      detail: facts.vulnerabilities.length ? `${facts.vulnerabilities.length} 个漏洞` : "未发现",
    });
  } else {
    sourceErrors.push({ source: "OSV.dev", message: osv.error ?? "查询失败" });
    sources.push({ name: "OSV.dev", status: "degraded", detail: osv.error });
  }

  if (github.status === "ok") {
    facts.stars = github.stars;
    sources.push({ name: "GitHub", status: "ok", detail: `${github.stars ?? 0} stars`, url: github.url });
  } else if (github.status === "skipped") {
    sources.push({ name: "GitHub", status: "degraded", detail: "未关联可解析的 GitHub 仓库" });
  } else {
    sourceErrors.push({ source: "GitHub", message: github.error ?? "查询失败" });
    sources.push({ name: "GitHub", status: "degraded", detail: github.error });
  }

  if (options.policy?.typosquatGuard !== false) {
    facts.typosquat = findTyposquat(ref.name, "npm");
  }

  sources.push(...sourceErrorsToSources(sourceErrors));
  return { facts, sources };
}

async function collectPypi(
  ref: PackageRef,
  options: Required<Pick<IntelOptions, "timeoutMs" | "now">> &
    IntelOptions & { fetchImpl: FetchLike },
  sources: SourceStatus[],
  sourceErrors: SourceError[],
): Promise<Collected> {
  const deadline = Date.now() + options.timeoutMs;
  const base = trimSlash(options.pypiRegistry ?? "https://pypi.org/pypi");
  const registryUrl = `${base}/${encodeURIComponent(ref.name)}/json`;
  const [registry, downloads] = await Promise.all([
    fetchJson(options.fetchImpl, registryUrl, { headers: { Accept: "application/json" } }, options.timeoutMs),
    fetchJson(
      options.fetchImpl,
      `https://pypistats.org/api/packages/${encodeURIComponent(ref.name.toLowerCase())}/recent`,
      { headers: { Accept: "application/json" } },
      options.timeoutMs,
    ),
  ]);

  const facts = emptyFacts(ref, registryUrl, false);
  facts.sourceErrors = sourceErrors;

  if (!registry.ok && registry.status === 404) {
    facts.lookupState = "not-found";
    sources.push({ name: "PyPI JSON API", status: "ok", detail: "404 · 未收录", url: registryUrl });
    sources.push({ name: "pypistats.org", status: "degraded", detail: downloads.error });
    return { facts, sources };
  }

  if (!registry.ok) {
    facts.lookupState = "error";
    facts.lookupError = registry.error ?? `PyPI JSON API HTTP ${registry.status}`;
    sources.push({
      name: "PyPI JSON API",
      status: "error",
      detail: facts.lookupError,
      url: registryUrl,
    });
    return { facts, sources };
  }

  const data = asRecord(registry.data);
  const info = asRecord(data.info);
  const releases = asRecord(data.releases);
  const latestVersion = asString(info.version);
  const requestedExact = ref.exactVersion ? ref.versionSpec : undefined;
  const version =
    requestedExact && releases[requestedExact] ? requestedExact : latestVersion;
  const projectUrls = asRecord(info.project_urls);
  const releaseFiles = version ? asArray(releases[version]) : [];
  const latestFile = releaseFiles
    .map(asRecord)
    .sort((a, b) => (asString(b.upload_time_iso_8601) ?? "").localeCompare(asString(a.upload_time_iso_8601) ?? ""))[0];

  if (!version && Object.keys(releases).length === 0) {
    facts.lookupState = "error";
    facts.lookupError = "PyPI 返回了无法解析的包元数据";
    sources.push({
      name: "PyPI JSON API",
      status: "error",
      detail: facts.lookupError,
      url: registryUrl,
    });
    return { facts, sources };
  }

  facts.found = true;
  facts.lookupState = "ok";
  facts.version = version;
  facts.requestedVersionMissing = Boolean(requestedExact && !releases[requestedExact]);
  facts.description = asString(info.summary);
  facts.homepage = asString(info.home_page) ?? firstString(projectUrls);
  facts.repositoryUrl = extractRepository(undefined, undefined, projectUrls);
  facts.license = normalizeLicense(info.license);
  facts.latestPublishedAt = asString(latestFile?.upload_time_iso_8601);
  facts.latestVersionCount = Object.keys(releases).length;

  const uploadTimes: string[] = [];
  for (const files of Object.values(releases)) {
    for (const file of asArray(files)) {
      const upload = asString(asRecord(file).upload_time_iso_8601);
      if (upload) {
        uploadTimes.push(upload);
      }
    }
  }
  const earliest = uploadTimes.sort()[0];
  if (earliest) {
    facts.createdAt = earliest;
    facts.ageDays = daysBetween(earliest, options.now);
  }

  if (downloads.ok) {
    const downloadsEnvelope = asRecord(downloads.data);
    const downloadsData = asRecord(downloadsEnvelope.data);
    const value =
      asNumber(downloadsData.last_week) ?? asNumber(downloadsEnvelope.last_week);
    if (value !== undefined) {
      facts.weeklyDownloads = value;
      facts.downloadsSource = "pypistats.org（第三方统计）";
    }
  } else {
    sourceErrors.push({ source: "pypistats.org", message: downloads.error ?? "请求失败" });
  }

  sources.push({
    name: "PyPI JSON API",
    status: "ok",
    detail: `${facts.latestVersionCount} 个版本`,
    url: registryUrl,
  });
  sources.push({
    name: "pypistats.org",
    status: downloads.ok ? "ok" : "degraded",
    detail: downloads.ok ? "last-week（第三方）" : downloads.error,
    url: `https://pypistats.org/packages/${encodeURIComponent(ref.name.toLowerCase())}`,
  });

  const remaining = Math.max(200, deadline - Date.now());
  const [osv, github] = await Promise.all([
    queryOsv(options.fetchImpl, ref.name, "PyPI", version, remaining),
    queryGitHub(options.fetchImpl, facts.repositoryUrl, options.githubToken, remaining),
  ]);

  if (osv.ok) {
    facts.vulnerabilities = mapOsvVulns(osv.data);
    sources.push({
      name: "OSV.dev",
      status: "ok",
      detail: facts.vulnerabilities.length ? `${facts.vulnerabilities.length} 个漏洞` : "未发现",
    });
  } else {
    sourceErrors.push({ source: "OSV.dev", message: osv.error ?? "查询失败" });
    sources.push({ name: "OSV.dev", status: "degraded", detail: osv.error });
  }

  if (github.status === "ok") {
    facts.stars = github.stars;
    sources.push({ name: "GitHub", status: "ok", detail: `${github.stars ?? 0} stars`, url: github.url });
  } else if (github.status === "skipped") {
    sources.push({ name: "GitHub", status: "degraded", detail: "未关联可解析的 GitHub 仓库" });
  } else {
    sourceErrors.push({ source: "GitHub", message: github.error ?? "查询失败" });
    sources.push({ name: "GitHub", status: "degraded", detail: github.error });
  }

  if (options.policy?.typosquatGuard !== false) {
    facts.typosquat = findTyposquat(ref.name, "pypi");
  }

  sources.push(...sourceErrorsToSources(sourceErrors));
  return { facts, sources };
}

export class PackageIntelService {
  private readonly cache = new Map<string, { expires: number; report: PackageReport }>();
  private options: IntelOptions;

  constructor(
    options: IntelOptions = {},
    private readonly ttlMs = 5 * 60 * 1000,
  ) {
    this.options = options;
  }

  setOptions(options: IntelOptions): void {
    this.options = options;
    this.clear();
  }

  async verify(ref: PackageRef, opts: { force?: boolean } = {}): Promise<PackageReport> {
    const key = `${ref.ecosystem}:${ref.name}:${ref.versionSpec ?? ""}:${ref.manager}:${
      this.options.npmRegistry ?? ""
    }`;
    const cached = this.cache.get(key);
    if (!opts.force && cached && cached.expires > Date.now()) {
      return cached.report;
    }
    const report = await verifyPackage(ref, this.options);
    this.cache.set(key, { expires: Date.now() + this.ttlMs, report });
    return report;
  }

  clear(): void {
    this.cache.clear();
  }
}

/* ------------------------------------------------------------------ */
/* HTTP + parsing helpers                                              */
/* ------------------------------------------------------------------ */

async function fetchJson(
  fetchImpl: FetchLike,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<FetchJsonResult> {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      ...init,
      signal: controller.signal,
      headers: {
        "User-Agent": USER_AGENT,
        ...(init.headers as Record<string, string> | undefined),
      },
    });
    const text = await response.text();
    let data: unknown;
    try {
      data = text ? JSON.parse(text) : undefined;
    } catch {
      data = text;
    }
    return {
      ok: response.ok,
      status: response.status,
      data,
      error: response.ok ? undefined : `HTTP ${response.status}`,
      url,
      durationMs: Date.now() - started,
    };
  } catch (error) {
    const isAbort = error instanceof Error && error.name === "AbortError";
    return {
      ok: false,
      status: 0,
      error: isAbort ? `请求超时（${timeoutMs}ms）` : error instanceof Error ? error.message : "网络错误",
      url,
      durationMs: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function queryOsv(
  fetchImpl: FetchLike,
  name: string,
  ecosystem: "npm" | "PyPI",
  version: string | undefined,
  timeoutMs: number,
): Promise<FetchJsonResult> {
  const payload: Record<string, unknown> = { package: { name, ecosystem } };
  if (version) {
    payload.version = version;
  }
  return fetchJson(
    fetchImpl,
    "https://api.osv.dev/v1/query",
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    },
    timeoutMs,
  );
}

type GithubResult =
  | { status: "ok"; stars?: number; url: string }
  | { status: "skipped" }
  | { status: "error"; error: string };

async function queryGitHub(
  fetchImpl: FetchLike,
  repositoryUrl: string | undefined,
  token: string | undefined,
  timeoutMs: number,
): Promise<GithubResult> {
  const slug = parseGitHubSlug(repositoryUrl);
  if (!slug) {
    return { status: "skipped" };
  }
  const url = `https://api.github.com/repos/${encodeURIComponent(slug.owner)}/${encodeURIComponent(slug.repo)}`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const result = await fetchJson(fetchImpl, url, { headers }, timeoutMs);
  if (!result.ok) {
    return {
      status: "error",
      error: result.status === 403 ? "GitHub API 限流" : (result.error ?? "请求失败"),
    };
  }
  const stars = asNumber(asRecord(result.data).stargazers_count);
  return { status: "ok", stars, url: `https://github.com/${slug.owner}/${slug.repo}` };
}

function mapOsvVulns(data: unknown): VulnerabilityInfo[] {
  const rawVulns = asArray(asRecord(data).vulns);
  const found = new Map<string, VulnerabilityInfo>();
  for (const raw of rawVulns) {
    const vuln = asRecord(raw);
    const id = asString(vuln.id);
    if (!id || found.has(id)) {
      continue;
    }
    const severity = osvSeverity(vuln);
    found.set(id, {
      id,
      summary: asString(vuln.summary) ?? asString(vuln.details)?.slice(0, 180) ?? "未提供摘要",
      severity,
      aliases: asArray(vuln.aliases).filter((a): a is string => typeof a === "string"),
      url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
    });
  }
  return [...found.values()].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity));
}

function osvSeverity(vuln: Record<string, unknown>): Severity {
  const databaseSpecific = asRecord(vuln.database_specific);
  const text = (asString(databaseSpecific.severity) ?? "").toUpperCase();
  if (text === "CRITICAL") return "critical";
  if (text === "HIGH") return "high";
  if (text === "MODERATE" || text === "MEDIUM") return "medium";
  if (text === "LOW") return "low";

  for (const entry of asArray(vuln.severity)) {
    const score = asString(asRecord(entry).score);
    if (!score) continue;
    if (/^\d+(\.\d+)?$/.test(score)) {
      const numeric = Number(score);
      if (numeric >= 9) return "critical";
      if (numeric >= 7) return "high";
      if (numeric >= 4) return "medium";
      return "low";
    }
    if (/C:H/i.test(score) && /I:H/i.test(score) && /A:H/i.test(score)) {
      return "high";
    }
  }
  return "medium";
}

function severityWeight(severity: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity];
}

function emptyFacts(ref: PackageRef, registryUrl: string, lookupError: boolean): PackageFacts {
  return {
    name: ref.name,
    ecosystem: ref.ecosystem,
    found: false,
    lookupState: lookupError ? "error" : "not-found",
    registryUrl,
    vulnerabilities: [],
    sourceErrors: [],
  };
}

function encodePackagePath(name: string): string {
  return encodeURIComponent(name).replace(/^%40/i, "@");
}

function trimSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function clampTimeout(value: number): number {
  return Math.min(10_000, Math.max(500, Math.round(value)));
}

function daysBetween(iso: string, now: Date): number | undefined {
  const time = Date.parse(iso);
  if (Number.isNaN(time)) {
    return undefined;
  }
  return Math.max(0, Math.floor((now.getTime() - time) / 86_400_000));
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function firstKey(record: Record<string, unknown>): string | undefined {
  return Object.keys(record)[0];
}

function firstString(record: Record<string, unknown>): string | undefined {
  for (const value of Object.values(record)) {
    if (typeof value === "string" && value) {
      return value;
    }
  }
  return undefined;
}

function normalizeLicense(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value.length > 80 ? `${value.slice(0, 80)}…` : value;
  }
  if (value && typeof value === "object") {
    return asString((value as Record<string, unknown>).type);
  }
  return undefined;
}

function earliestTime(time: Record<string, unknown>): string | undefined {
  const times = Object.values(time)
    .filter((value): value is string => typeof value === "string" && !Number.isNaN(Date.parse(value)))
    .sort();
  return times[0];
}

function extractRepository(
  repository: unknown,
  homepage?: string,
  projectUrls?: Record<string, unknown>,
): string | undefined {
  const candidates: string[] = [];
  if (typeof repository === "string") {
    candidates.push(repository);
  } else if (repository && typeof repository === "object") {
    const url = asString((repository as Record<string, unknown>).url);
    if (url) candidates.push(url);
  }
  if (projectUrls) {
    for (const [key, value] of Object.entries(projectUrls)) {
      if (typeof value === "string" && /(source|repo|code|homepage|github)/i.test(key)) {
        candidates.push(value);
      }
    }
  }
  if (homepage) candidates.push(homepage);

  for (const candidate of candidates) {
    const slug = parseGitHubSlug(candidate);
    if (slug) {
      return `https://github.com/${slug.owner}/${slug.repo}`;
    }
  }
  return candidates.find((value) => /^https?:\/\//i.test(value));
}

export function parseGitHubSlug(value: string | undefined): { owner: string; repo: string } | undefined {
  if (!value) {
    return undefined;
  }
  const match =
    /github\.com[/:]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[#/?].*)?$/i.exec(
      value.trim(),
    ) ?? /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(value.trim());
  if (!match) {
    return undefined;
  }
  return { owner: match[1]!, repo: match[2]! };
}

function sourceErrorsToSources(errors: SourceError[]): SourceStatus[] {
  return errors.length
    ? [
        {
          name: "数据完整性",
          status: "degraded",
          detail: `${errors.length} 个数据源不可用，结论已降级`,
        },
      ]
    : [];
}
