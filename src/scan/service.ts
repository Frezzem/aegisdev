import * as vscode from "vscode";
import {
  AGENT_CONFIG_GLOBS,
  isAgentConfigPath,
  SCAN_EXCLUDE_GLOB,
} from "../config.js";
import { countSeverities, scanContent, severityRank } from "../core/unicode.js";
import type { FileScanResult, ScanReport, Severity } from "../core/types.js";

export interface ScanTarget {
  uri: vscode.Uri;
  display: string;
}

export interface WorkspaceScan {
  report: ScanReport;
  uriMap: Map<string, vscode.Uri>;
}

const MAX_FILE_BYTES = 1_500_000;

export async function discoverScanTargets(maxFiles: number): Promise<ScanTarget[]> {
  const seen = new Set<string>();
  const targets: ScanTarget[] = [];

  for (const pattern of AGENT_CONFIG_GLOBS) {
    let uris: vscode.Uri[] = [];
    try {
      uris = await vscode.workspace.findFiles(pattern, SCAN_EXCLUDE_GLOB, maxFiles * 2);
    } catch {
      continue;
    }
    for (const uri of uris) {
      if (!isAgentConfigPath(uri.fsPath)) {
        continue;
      }
      const key = uri.toString();
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      targets.push({
        uri,
        display: vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/"),
      });
      if (targets.length >= maxFiles) {
        return targets.sort((a, b) => a.display.localeCompare(b.display));
      }
    }
  }

  return targets.sort((a, b) => a.display.localeCompare(b.display));
}

export async function scanWorkspace(maxFiles: number): Promise<WorkspaceScan> {
  const started = Date.now();
  const targets = await discoverScanTargets(maxFiles);
  const results: FileScanResult[] = [];
  const uriMap = new Map<string, vscode.Uri>();
  let skippedFiles = 0;

  const concurrency = 8;
  for (let index = 0; index < targets.length; index += concurrency) {
    const chunk = targets.slice(index, index + concurrency);
    const scanned = await Promise.all(
      chunk.map(async (target) => {
        const text = await readTextFile(target.uri);
        if (text === undefined) {
          skippedFiles += 1;
          return undefined;
        }
        const result = scanContent(text, target.display, languageHintFor(target.uri));
        result.sanitized = undefined;
        return { result, uri: target.uri };
      }),
    );
    for (const item of scanned) {
      if (!item) {
        continue;
      }
      results.push(item.result);
      uriMap.set(item.result.file, item.uri);
    }
  }

  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "当前工作区";
  return {
    report: buildScanReport(results, root, "workspace", Date.now() - started, skippedFiles),
    uriMap,
  };
}

export function scanDocument(document: vscode.TextDocument): FileScanResult {
  const display =
    document.uri.scheme === "file"
      ? vscode.workspace.asRelativePath(document.uri, false).replace(/\\/g, "/")
      : document.uri.toString();
  const result = scanContent(document.getText(), display, document.languageId);
  result.sanitized = undefined;
  return result;
}

export function buildScanReport(
  files: FileScanResult[],
  root: string,
  scope: "workspace" | "file",
  durationMs: number,
  skippedFiles = 0,
): ScanReport {
  const findings = files.flatMap((file) => file.findings);
  const counts = countSeverities(findings);
  const filesWithFindings = files.filter((file) => file.findings.length > 0).length;
  const hasCritical = counts.critical > 0;
  const hasHigh = counts.high > 0;
  const verdict: ScanReport["verdict"] = hasCritical
    ? "critical"
    : hasHigh || counts.medium > 0 || counts.low > 0 || skippedFiles > 0
      ? "review"
      : "clean";

  const scopeLabel = scope === "file" ? "当前文件" : `${files.length} 个 Agent 配置文件`;
  const skippedNote =
    skippedFiles > 0
      ? ` 另有 ${skippedFiles} 个文件因超过 1.5MB、二进制或无法读取而被跳过。`
      : "";
  const headline =
    verdict === "critical"
      ? `发现 ${counts.critical} 处严重隐藏字符`
      : verdict === "review"
        ? findings.length > 0
          ? `发现 ${findings.length} 处可疑隐藏字符`
          : "扫描完成，但有文件被跳过"
        : "配置干净，未发现隐藏字符";

  const summary =
    verdict === "critical"
      ? `在 ${filesWithFindings} 个${scope === "file" ? "文件" : "配置文件"}中发现 Tag 字符 / 双向控制符等隐藏内容。AI Agent 可能把其中的指令当作上下文执行，请立即清理。${skippedNote}`
      : verdict === "review"
        ? findings.length > 0
          ? `发现零宽字符、不可见填充符或同形字令牌，可能隐藏内容或绕过关键词检测。建议人工确认后清理。${skippedNote}`
          : `已扫描 ${scopeLabel}，但${skippedNote.trim() || "部分文件未能读取"}请人工检查这些文件。`
        : `已扫描 ${scopeLabel}，未发现 Unicode 隐藏字符。Aegis 仍建议定期人工审查 Agent 配置的变更。`;

  const sortedFindings = [...findings].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      a.file.localeCompare(b.file) ||
      a.index - b.index,
  );
  const sortedFiles = [...files].sort(
    (a, b) =>
      severityRank(toSeverity(b.risk)) - severityRank(toSeverity(a.risk)) ||
      a.file.localeCompare(b.file),
  );

  return {
    kind: "scan",
    root,
    scope,
    scannedAt: new Date().toISOString(),
    durationMs,
    filesScanned: files.length,
    skippedFiles,
    filesWithFindings,
    findings: sortedFindings,
    files: sortedFiles,
    counts,
    verdict,
    headline,
    summary,
    privacy: "所有扫描与净化均在本机完成，文件内容不会上传到任何服务器。",
  };
}

export async function readTextFile(uri: vscode.Uri): Promise<string | undefined> {
  try {
    const stat = await vscode.workspace.fs.stat(uri);
    if (stat.size > MAX_FILE_BYTES) {
      return undefined;
    }
    const bytes = await vscode.workspace.fs.readFile(uri);
    if (bytes.length > MAX_FILE_BYTES) {
      return undefined;
    }
    // Skip files that look binary rather than dumping replacement characters
    // into a security report.
    const sample = bytes.subarray(0, Math.min(bytes.length, 4096));
    if (sample.includes(0)) {
      return undefined;
    }
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return undefined;
  }
}

function languageHintFor(uri: vscode.Uri): string {
  const extension = uri.path.split(".").pop()?.toLowerCase() ?? "";
  return (
    {
      json: "json",
      jsonc: "jsonc",
      yml: "yaml",
      yaml: "yaml",
      md: "markdown",
      mdc: "markdown",
      toml: "toml",
    }[extension] ?? "plaintext"
  );
}

function toSeverity(risk: Severity | "none"): Severity {
  return risk === "none" ? "info" : risk;
}
