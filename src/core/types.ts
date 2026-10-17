export type Ecosystem = "npm" | "pypi";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Verdict = "allow" | "review" | "block";

export type SignalStatus = "good" | "warn" | "bad" | "unknown";

export interface PackageRef {
  ecosystem: Ecosystem;
  name: string;
  /** Version / range exactly as requested, without the leading @ or ==. */
  versionSpec?: string;
  /** Whether the version spec is a pinned exact version (no range operators). */
  exactVersion: boolean;
  /** Safe, rebuilt installation command. Never contains the raw user input. */
  installCommand: string;
  /** Human-readable package manager label, e.g. npm / pnpm / pip. */
  manager: string;
  /** Original input, kept for display only. */
  raw: string;
  /** The package spec as it should be passed to the installer, e.g. @scope/pkg@^1. */
  spec: string;
}

export interface PackageFacts {
  name: string;
  ecosystem: Ecosystem;
  found: boolean;
  /** ok = registry answered; not-found = 404; error = timeout/network/5xx. */
  lookupState: "ok" | "not-found" | "error";
  /** True when an exact version was requested but is absent from the registry. */
  requestedVersionMissing?: boolean;
  lookupError?: string;
  version?: string;
  description?: string;
  homepage?: string;
  repositoryUrl?: string;
  registryUrl: string;
  createdAt?: string;
  latestPublishedAt?: string;
  ageDays?: number;
  weeklyDownloads?: number;
  downloadsSource?: string;
  stars?: number;
  maintainers?: number;
  license?: string;
  deprecated?: boolean;
  hasInstallScript?: boolean;
  latestVersionCount?: number;
  vulnerabilities: VulnerabilityInfo[];
  typosquat?: TyposquatInfo;
  sourceErrors: SourceError[];
}

export interface VulnerabilityInfo {
  id: string;
  summary: string;
  severity: Severity;
  aliases?: string[];
  url?: string;
}

export interface TyposquatInfo {
  popularName: string;
  distance: number;
}

export interface SourceError {
  source: string;
  message: string;
}

export interface PackageSignal {
  key: string;
  label: string;
  value: string;
  status: SignalStatus;
  detail?: string;
}

export interface Evidence {
  severity: Severity;
  title: string;
  detail: string;
}

export interface SourceStatus {
  name: string;
  status: "ok" | "degraded" | "error";
  detail?: string;
  url?: string;
}

export interface Assessment {
  verdict: Verdict;
  score: number;
  headline: string;
  summary: string;
  signals: PackageSignal[];
  evidence: Evidence[];
  allowlisted: boolean;
  blockedByPolicy: boolean;
}

export interface PackageReport {
  kind: "package";
  ref: PackageRef;
  facts: PackageFacts;
  assessment: Assessment;
  sources: SourceStatus[];
  generatedAt: string;
  durationMs: number;
  privacy: string;
}

/* ------------------------------------------------------------------ */
/* Unicode scanner                                                     */
/* ------------------------------------------------------------------ */

export type FindingCategory =
  | "tag"
  | "bidi"
  | "zero-width"
  | "variation-selector"
  | "invisible"
  | "homoglyph"
  | "escaped";

export interface UnicodeFinding {
  id: string;
  file: string;
  /** 1-based line number. */
  line: number;
  /** 1-based UTF-16 column. */
  column: number;
  /** UTF-16 offset of the finding inside the file. */
  index: number;
  /** Number of UTF-16 code units covered by this finding. */
  length: number;
  codePoint: number;
  hex: string;
  name: string;
  category: FindingCategory;
  severity: Severity;
  /** Line content with invisible characters rendered as ⟨U+XXXX⟩. */
  context: string;
  /** Decoded ASCII payload for tag-character runs. */
  decoded?: string;
  message: string;
  /** Whether the payload contains shell / exfiltration indicators. */
  payloadRisk?: "high" | "medium" | "none";
  /** Whether the character range can be removed automatically. */
  fixable: boolean;
}

export interface FileScanResult {
  file: string;
  languageHint: string;
  size: number;
  findings: UnicodeFinding[];
  risk: Severity | "none";
  /** Sanitized content, only kept for files with findings. */
  sanitized?: string;
}

export interface ScanReport {
  kind: "scan";
  root: string;
  scope: "workspace" | "file";
  scannedAt: string;
  durationMs: number;
  filesScanned: number;
  /** Files skipped because they were too large, binary or unreadable. */
  skippedFiles: number;
  filesWithFindings: number;
  findings: UnicodeFinding[];
  files: FileScanResult[];
  counts: Record<Severity, number>;
  verdict: "clean" | "review" | "critical";
  headline: string;
  summary: string;
  privacy: string;
}

export interface ScanTarget {
  file: string;
  languageHint: string;
}
