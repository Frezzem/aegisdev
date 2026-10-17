import * as vscode from "vscode";
import { readIntelOptions } from "./config.js";
import {
  copyInstallCommand,
  openRegistry,
  recheckPackage,
  verifyPackageInteractive,
} from "./commands/packages.js";
import {
  previewSanitizedCommand,
  registerScanOnSave,
  removeFindingCommand,
  runScanCommand,
  sanitizeAllCommand,
  sanitizeFileCommand,
  scanCurrentFileCommand,
  scheduleAutoScan,
} from "./commands/scan.js";
import { PackageIntelService } from "./core/intel.js";
import type { PackageReport, ScanReport } from "./core/types.js";
import type { AegisDeps } from "./deps.js";
import { AegisCodeActionProvider } from "./scan/codeActions.js";
import { AegisState } from "./state.js";
import { DashboardProvider } from "./ui/dashboard.js";
import { PreviewProvider } from "./ui/preview.js";
import { ReportPanel, type ReportAction } from "./ui/reportPanel.js";
import { StatusController } from "./ui/status.js";

export function activate(context: vscode.ExtensionContext): void {
  const version =
    typeof context.extension.packageJSON.version === "string"
      ? context.extension.packageJSON.version
      : "1.0.0";
  const output = vscode.window.createOutputChannel("AegisDev");
  const state = new AegisState();
  const diagnostics = vscode.languages.createDiagnosticCollection("aegis");
  const previews = new PreviewProvider();
  const intel = new PackageIntelService(readIntelOptions());
  const status = new StatusController();
  const dashboard = new DashboardProvider(state);
  const tree = vscode.window.createTreeView("aegis.dashboard", {
    treeDataProvider: dashboard,
    showCollapseAll: false,
  });
  const reports = new ReportPanel(context.extensionUri, version);

  const deps: AegisDeps = {
    context,
    intel,
    state,
    reports,
    dashboard,
    status,
    diagnostics,
    previews,
    output,
    version,
  };

  context.subscriptions.push(
    output,
    diagnostics,
    status,
    tree,
    reports,
    vscode.workspace.registerTextDocumentContentProvider("aegis-preview", previews),
    vscode.languages.registerCodeActionsProvider(
      [{ scheme: "file" }, { scheme: "untitled" }],
      new AegisCodeActionProvider(),
      { providedCodeActionKinds: AegisCodeActionProvider.providedCodeActionKinds },
    ),
    reports.onDidAction((action) => {
      void handleReportAction(deps, action);
    }),
    vscode.commands.registerCommand("aegis.verifyPackage", () =>
      verifyPackageInteractive(deps),
    ),
    vscode.commands.registerCommand("aegis.verifyAndInstall", () =>
      verifyPackageInteractive(deps, { install: true }),
    ),
    vscode.commands.registerCommand("aegis.scanAgentConfigs", () =>
      runScanCommand(deps),
    ),
    vscode.commands.registerCommand("aegis.scanCurrentFile", () =>
      scanCurrentFileCommand(deps),
    ),
    vscode.commands.registerCommand("aegis.openReport", (kind?: string) =>
      openReport(deps, kind),
    ),
    vscode.commands.registerCommand("aegis.openDashboard", () =>
      vscode.commands.executeCommand("workbench.view.extension.aegis"),
    ),
    vscode.commands.registerCommand("aegis.refreshDashboard", () => dashboard.refresh()),
    vscode.commands.registerCommand("aegis.openSettings", () =>
      vscode.commands.executeCommand("workbench.action.openSettings", "aegis"),
    ),
    vscode.commands.registerCommand("aegis.showOutput", () => output.show(true)),
    vscode.commands.registerCommand("aegis.previewSanitized", (uri?: vscode.Uri) =>
      previewSanitizedCommand(deps, uri),
    ),
    vscode.commands.registerCommand("aegis.sanitizeFile", (uri?: vscode.Uri) =>
      sanitizeFileCommand(deps, uri),
    ),
    vscode.commands.registerCommand("aegis.sanitizeAll", () => sanitizeAllCommand(deps)),
    vscode.commands.registerCommand("aegis.removeFinding", (id: string) =>
      removeFindingCommand(deps, id),
    ),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("aegis")) {
        intel.setOptions(readIntelOptions());
        dashboard.refresh();
      }
    }),
    registerScanOnSave(deps),
  );

  output.appendLine(`[activate] AegisDev v${version}`);
  output.appendLine(
    "[privacy] 静态扫描与净化在本地执行；依赖核验只发送包名、版本与公开元数据。",
  );

  void scheduleAutoScan(deps);
}

export function deactivate(): void {
  // All resources are registered in context.subscriptions.
}

async function handleReportAction(deps: AegisDeps, action: ReportAction): Promise<void> {
  try {
    switch (action.type) {
      case "copyInstall":
        await copyInstallCommand(deps);
        break;
      case "recheck":
        await recheckPackage(deps);
        break;
      case "openRegistry":
        await openRegistry(deps);
        break;
      case "rescan":
        await runScanCommand(deps);
        break;
      case "sanitizeAll":
        await sanitizeAllCommand(deps);
        break;
      case "sanitizeFile": {
        if (!action.file) {
          return;
        }
        const uri = deps.state.scanTargets.get(action.file);
        if (!uri) {
          void vscode.window.showInformationMessage("Aegis: 未找到该文件，请重新扫描。");
          return;
        }
        await sanitizeFileCommand(deps, uri);
        break;
      }
      case "fixFinding":
        if (action.id) {
          await removeFindingCommand(deps, action.id);
        }
        break;
      case "openFinding":
        if (action.id) {
          await openFinding(deps, action.id);
        }
        break;
      case "openDashboard":
        await vscode.commands.executeCommand("workbench.view.extension.aegis");
        break;
      default:
        break;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    deps.output.appendLine(`[action:${action.type}] failed: ${message}`);
    void vscode.window.showErrorMessage(`Aegis 操作失败：${message}`);
  }
}

async function openFinding(deps: AegisDeps, id: string): Promise<void> {
  const finding = deps.state.lastScan?.findings.find((item) => item.id === id);
  if (!finding) {
    void vscode.window.showInformationMessage("Aegis: 未找到该条发现，请重新扫描。");
    return;
  }
  const uri = deps.state.scanTargets.get(finding.file);
  if (!uri) {
    void vscode.window.showInformationMessage("Aegis: 未找到对应文件。");
    return;
  }
  const document = await vscode.workspace.openTextDocument(uri);
  const line = Math.min(Math.max(0, finding.line - 1), Math.max(0, document.lineCount - 1));
  const lineText = document.lineAt(line).text;
  const start = Math.min(Math.max(0, finding.column - 1), lineText.length);
  const range = new vscode.Range(line, start, line, Math.min(start + finding.length, lineText.length));
  await vscode.window.showTextDocument(document, {
    viewColumn: vscode.ViewColumn.One,
    selection: range,
    preserveFocus: false,
  });
}

async function openReport(deps: AegisDeps, kind?: string): Promise<void> {
  if (kind === "package" || kind === "scan") {
    const report =
      kind === "package" ? deps.state.lastPackageReport : deps.state.lastScan;
    if (report) {
      deps.reports.show(report);
      return;
    }
  }

  const candidates: Array<PackageReport | ScanReport> = [];
  if (deps.state.lastPackageReport) {
    candidates.push(deps.state.lastPackageReport);
  }
  if (deps.state.lastScan) {
    candidates.push(deps.state.lastScan);
  }
  if (candidates.length === 0) {
    void vscode.window.showInformationMessage("Aegis: 还没有安全报告，请先运行核验或扫描。");
    return;
  }
  candidates.sort((a, b) => reportTime(b) - reportTime(a));
  deps.reports.show(candidates[0]!);
}

function reportTime(report: PackageReport | ScanReport): number {
  return Date.parse(report.kind === "package" ? report.generatedAt : report.scannedAt) || 0;
}
