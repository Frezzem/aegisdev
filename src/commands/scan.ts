import * as vscode from "vscode";
import { isAgentConfigPath, readScanSettings } from "../config.js";
import { sanitizeText, scanContent } from "../core/unicode.js";
import type { ScanReport, UnicodeFinding } from "../core/types.js";
import type { AegisDeps } from "../deps.js";
import { buildScanReport, scanDocument, scanWorkspace } from "../scan/service.js";
import {
  updateDiagnosticsForFile,
  updateDiagnosticsForReport,
} from "../scan/diagnostics.js";

let didNotifyAutoScan = false;

export async function runScanCommand(
  deps: AegisDeps,
  options: { silent?: boolean } = {},
): Promise<ScanReport | undefined> {
  if (!vscode.workspace.workspaceFolders?.length) {
    if (vscode.window.activeTextEditor) {
      return scanCurrentFileCommand(deps);
    }
    void vscode.window.showInformationMessage("Aegis: 请先打开一个工作区文件夹。");
    return undefined;
  }

  const task = () =>
    performWorkspaceScan(deps, { show: options.silent !== true, silent: options.silent === true });

  if (options.silent) {
    return task();
  }

  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Aegis 正在扫描 Agent 配置",
      cancellable: false,
    },
    task,
  );
}

async function performWorkspaceScan(
  deps: AegisDeps,
  options: { show: boolean; silent: boolean },
): Promise<ScanReport> {
  const settings = readScanSettings();
  const { report, uriMap } = await scanWorkspace(settings.maxScanFiles);

  deps.state.lastScan = report;
  deps.state.scanTargets = uriMap;
  updateDiagnosticsForReport(deps.diagnostics, report, uriMap);
  deps.dashboard.refresh();
  deps.status.setScan(report);
  deps.output.appendLine(
    `[scan] ${report.filesScanned} files, ${report.findings.length} findings ` +
      `(critical=${report.counts.critical}) in ${report.durationMs}ms`,
  );
  for (const file of report.files.filter((item) => item.findings.length > 0)) {
    deps.output.appendLine(
      `  - ${file.file}: ${file.findings.length} finding(s), risk=${file.risk}`,
    );
  }

  if (options.show) {
    deps.reports.show(report);
  } else if (
    report.verdict === "critical" &&
    options.silent &&
    !didNotifyAutoScan
  ) {
    didNotifyAutoScan = true;
    const action = await vscode.window.showWarningMessage(
      `Aegis: 在 ${report.filesWithFindings} 个 Agent 配置中发现隐藏字符。`,
      "查看报告",
      "稍后",
    );
    if (action === "查看报告") {
      deps.reports.show(report);
    }
  }

  return report;
}

export async function scanCurrentFileCommand(
  deps: AegisDeps,
  document?: vscode.TextDocument,
): Promise<ScanReport | undefined> {
  const doc = document ?? vscode.window.activeTextEditor?.document;
  if (!doc) {
    void vscode.window.showInformationMessage("Aegis: 请先打开一个文件。");
    return undefined;
  }

  const started = Date.now();
  const result = scanDocument(doc);
  const report = buildScanReport([result], doc.uri.fsPath || doc.uri.toString(), "file", Date.now() - started);

  deps.state.lastScan = report;
  deps.state.scanTargets = new Map([[result.file, doc.uri]]);
  updateDiagnosticsForFile(deps.diagnostics, result, doc.uri);
  deps.dashboard.refresh();
  deps.status.setScan(report);
  deps.reports.show(report);
  deps.output.appendLine(
    `[scan:file] ${result.file}: ${result.findings.length} finding(s) in ${report.durationMs}ms`,
  );

  return report;
}

export async function sanitizeFileCommand(
  deps: AegisDeps,
  target?: vscode.Uri,
): Promise<void> {
  const uri = target ?? vscode.window.activeTextEditor?.document.uri;
  if (!uri) {
    void vscode.window.showInformationMessage("Aegis: 未找到要净化的文件。");
    return;
  }
  if (!ensureWritable(uri)) {
    return;
  }

  const document = await vscode.workspace.openTextDocument(uri);
  const display = displayName(document.uri);
  const current = scanContent(document.getText(), display, document.languageId);
  const fixable = current.findings.filter((finding) => finding.fixable);
  if (fixable.length === 0) {
    void vscode.window.showInformationMessage("Aegis: 该文件没有可自动移除的隐藏字符。");
    return;
  }

  const confirm = await vscode.window.showWarningMessage(
    `Aegis 将从 ${display} 移除 ${fixable.length} 处隐藏字符并保存。是否继续？`,
    { modal: true },
    "净化并保存",
  );
  if (confirm !== "净化并保存") {
    return;
  }

  const removed = await deleteFindings(document, current.findings);
  void vscode.window.showInformationMessage(`Aegis: 已从 ${display} 移除 ${removed} 处隐藏字符。`);
  await refreshAfterFix(deps, uri);
}

export async function removeFindingCommand(deps: AegisDeps, id: string): Promise<void> {
  const finding = deps.state.lastScan?.findings.find((item) => item.id === id);
  if (!finding) {
    void vscode.window.showInformationMessage("Aegis: 未找到该条发现，请重新扫描。");
    return;
  }
  const uri = deps.state.scanTargets.get(finding.file);
  if (!uri) {
    void vscode.window.showInformationMessage("Aegis: 未找到对应文件，请重新扫描。");
    return;
  }
  if (!finding.fixable) {
    void vscode.window.showWarningMessage("Aegis: 同形字伪装需要人工重写，不能自动删除。");
    return;
  }
  if (!ensureWritable(uri)) {
    return;
  }

  const document = await vscode.workspace.openTextDocument(uri);
  const current = scanContent(document.getText(), displayName(uri), document.languageId);
  const match = current.findings.find((item) => item.id === id);
  if (!match) {
    void vscode.window.showInformationMessage("Aegis: 文件已变化，未找到该隐藏字符，请重新扫描。");
    return;
  }

  await deleteFindings(document, [match]);
  void vscode.window.showInformationMessage("Aegis: 已移除 1 处隐藏字符。");
  await refreshAfterFix(deps, uri);
}

export async function sanitizeAllCommand(deps: AegisDeps): Promise<void> {
  const report = deps.state.lastScan;
  if (!report) {
    void vscode.window.showInformationMessage("Aegis: 请先运行一次配置扫描。");
    return;
  }
  const affected = report.files.filter((file) => file.findings.some((finding) => finding.fixable));
  if (affected.length === 0) {
    void vscode.window.showInformationMessage("Aegis: 没有可自动净化的隐藏字符。");
    return;
  }
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage("Aegis: 受限模式下不允许修改工作区文件。");
    return;
  }

  const total = affected.reduce(
    (sum, file) => sum + file.findings.filter((finding) => finding.fixable).length,
    0,
  );
  const confirm = await vscode.window.showWarningMessage(
    `Aegis 将从 ${affected.length} 个配置文件移除 ${total} 处隐藏字符并保存。建议先预览或提交 Git 快照。`,
    { modal: true },
    "净化并保存",
  );
  if (confirm !== "净化并保存") {
    return;
  }

  let filesChanged = 0;
  let removed = 0;
  const failures: string[] = [];
  for (const file of affected) {
    const uri = deps.state.scanTargets.get(file.file);
    if (!uri || !ensureWritable(uri, false)) {
      failures.push(file.file);
      continue;
    }
    try {
      const document = await vscode.workspace.openTextDocument(uri);
      const current = scanContent(document.getText(), file.file, document.languageId);
      if (!current.findings.some((finding) => finding.fixable)) {
        continue;
      }
      const count = await deleteFindings(document, current.findings);
      removed += count;
      filesChanged += 1;
    } catch {
      failures.push(file.file);
    }
  }

  if (removed > 0) {
    void vscode.window.showInformationMessage(
      `Aegis: 已净化 ${filesChanged} 个文件，移除 ${removed} 处隐藏字符。`,
    );
  }
  if (failures.length > 0) {
    void vscode.window.showWarningMessage(
      `Aegis: ${failures.length} 个文件未能净化（可能已关闭、无权限或内容已变化）。`,
    );
  }
  await refreshAfterFix(deps, affected[0] ? deps.state.scanTargets.get(affected[0].file) : undefined);
}

export async function previewSanitizedCommand(
  deps: AegisDeps,
  target?: vscode.Uri,
): Promise<void> {
  const uri = target ?? vscode.window.activeTextEditor?.document.uri;
  if (!uri) {
    void vscode.window.showInformationMessage("Aegis: 请先打开一个文件。");
    return;
  }
  const document = await vscode.workspace.openTextDocument(uri);
  const current = scanContent(document.getText(), displayName(uri), document.languageId);
  const fixable = current.findings.filter((finding) => finding.fixable);
  if (fixable.length === 0) {
    void vscode.window.showInformationMessage("Aegis: 该文件没有可自动移除的隐藏字符。");
    return;
  }
  const sanitized = sanitizeText(document.getText(), current.findings);
  const previewUri = deps.previews.createUri(uri.path.split("/").pop() ?? "preview");
  deps.previews.set(previewUri, sanitized);
  await vscode.commands.executeCommand(
    "vscode.diff",
    document.uri,
    previewUri,
    `Aegis 净化预览 · ${displayName(uri)}`,
  );
}

async function refreshAfterFix(deps: AegisDeps, preferred?: vscode.Uri): Promise<void> {
  const previous = deps.state.lastScan;
  if (previous?.scope === "file" && preferred) {
    const document = await vscode.workspace.openTextDocument(preferred);
    const result = scanDocument(document);
    const report = buildScanReport(
      [result],
      preferred.fsPath,
      "file",
      0,
    );
    deps.state.lastScan = report;
    deps.state.scanTargets = new Map([[result.file, preferred]]);
    updateDiagnosticsForFile(deps.diagnostics, result, preferred);
    deps.dashboard.refresh();
    deps.status.setScan(report);
    deps.reports.show(report);
    return;
  }

  const settings = readScanSettings();
  if (vscode.workspace.workspaceFolders?.length) {
    const { report, uriMap } = await scanWorkspace(settings.maxScanFiles);
    deps.state.lastScan = report;
    deps.state.scanTargets = uriMap;
    updateDiagnosticsForReport(deps.diagnostics, report, uriMap);
    deps.dashboard.refresh();
    deps.status.setScan(report);
    deps.reports.show(report);
  }
}

async function deleteFindings(
  document: vscode.TextDocument,
  findings: UnicodeFinding[],
): Promise<number> {
  const fixable = findings
    .filter((finding) => finding.fixable)
    .sort((a, b) => b.index - a.index);
  const edit = new vscode.WorkspaceEdit();
  let lastStart = Number.POSITIVE_INFINITY;
  let applied = 0;

  for (const finding of fixable) {
    if (finding.index + finding.length > lastStart) {
      continue;
    }
    const range = new vscode.Range(
      document.positionAt(finding.index),
      document.positionAt(finding.index + finding.length),
    );
    edit.delete(document.uri, range);
    lastStart = finding.index;
    applied += 1;
  }

  if (applied === 0) {
    return 0;
  }
  const ok = await vscode.workspace.applyEdit(edit);
  if (!ok) {
    throw new Error("无法应用净化编辑");
  }
  const saved = await document.save();
  if (!saved) {
    void vscode.window.showWarningMessage("Aegis: 净化已应用，但文件未能自动保存，请手动保存。");
  }
  return applied;
}

function ensureWritable(uri: vscode.Uri, notify = true): boolean {
  if (!vscode.workspace.isTrusted) {
    if (notify) {
      void vscode.window.showWarningMessage("Aegis: 受限模式下不允许修改工作区文件。");
    }
    return false;
  }
  if (uri.scheme !== "file") {
    if (notify) {
      void vscode.window.showWarningMessage("Aegis: 仅支持净化本地文件。");
    }
    return false;
  }
  return true;
}

function displayName(uri: vscode.Uri): string {
  return vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/");
}

export function registerScanOnSave(deps: AegisDeps): vscode.Disposable {
  return vscode.workspace.onDidSaveTextDocument((document) => {
    const settings = readScanSettings();
    if (
      !settings.scanOnSave ||
      document.uri.scheme !== "file" ||
      !isAgentConfigPath(document.uri.fsPath)
    ) {
      return;
    }
    const result = scanDocument(document);
    updateDiagnosticsForFile(deps.diagnostics, result, document.uri);
    if (result.findings.some((finding) => finding.severity === "critical")) {
      void vscode.window.setStatusBarMessage(
        "Aegis: 已保存的 Agent 配置仍包含严重隐藏字符",
        5000,
      );
    }
  });
}

export async function scheduleAutoScan(deps: AegisDeps): Promise<void> {
  const settings = readScanSettings();
  if (!settings.scanOnOpen || !vscode.workspace.workspaceFolders?.length) {
    return;
  }
  await new Promise((resolve) => setTimeout(resolve, 1200));
  try {
    await runScanCommand(deps, { silent: true });
  } catch (error) {
    deps.output.appendLine(`[auto-scan] failed: ${error instanceof Error ? error.message : error}`);
  }
}
