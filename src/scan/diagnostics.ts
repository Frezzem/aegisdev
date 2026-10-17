import * as vscode from "vscode";
import type { FileScanResult, ScanReport, Severity, UnicodeFinding } from "../core/types.js";

export function updateDiagnosticsForReport(
  collection: vscode.DiagnosticCollection,
  report: ScanReport,
  uriMap: Map<string, vscode.Uri>,
): void {
  collection.clear();
  for (const file of report.files) {
    if (file.findings.length === 0) {
      continue;
    }
    const uri = uriMap.get(file.file);
    if (!uri) {
      continue;
    }
    collection.set(uri, toDiagnostics(file));
  }
}

export function updateDiagnosticsForFile(
  collection: vscode.DiagnosticCollection,
  file: FileScanResult,
  uri: vscode.Uri,
): void {
  if (file.findings.length === 0) {
    collection.delete(uri);
    return;
  }
  collection.set(uri, toDiagnostics(file));
}

export function toDiagnostics(file: FileScanResult): vscode.Diagnostic[] {
  return file.findings.map((finding) => toDiagnostic(finding));
}

function toDiagnostic(finding: UnicodeFinding): vscode.Diagnostic {
  const line = Math.max(0, finding.line - 1);
  const start = Math.max(0, finding.column - 1);
  const range = new vscode.Range(line, start, line, start + finding.length);
  const diagnostic = new vscode.Diagnostic(
    range,
    `Aegis: ${finding.message}${
      finding.decoded ? ` 解码内容：${truncate(finding.decoded, 120)}` : ""
    }`,
    severityToDiagnostic(finding.severity),
  );
  diagnostic.source = "AegisDev";
  diagnostic.code = "hidden-unicode";
  return diagnostic;
}

function severityToDiagnostic(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}
