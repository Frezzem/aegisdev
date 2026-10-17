import * as vscode from "vscode";
import { readIntelOptions } from "../config.js";
import { parsePackageInput, PackageInputError } from "../core/input.js";
import type { PackageRef, PackageReport } from "../core/types.js";
import type { AegisDeps } from "../deps.js";

export interface VerifyOptions {
  install?: boolean;
  force?: boolean;
  ref?: PackageRef;
  notify?: boolean;
}

export async function verifyPackageInteractive(
  deps: AegisDeps,
  options: VerifyOptions = {},
): Promise<PackageReport | undefined> {
  let ref = options.ref;
  if (!ref) {
    const input = await promptForPackage();
    if (!input) {
      return undefined;
    }
    try {
      ref = parsePackageInput(input);
    } catch (error) {
      const message = error instanceof PackageInputError ? error.message : "无法解析包名。";
      void vscode.window.showWarningMessage(`Aegis: ${message}`);
      return undefined;
    }
  }

  deps.intel.setOptions(readIntelOptions());
  const report = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Aegis 正在核验 ${ref.name}`,
      cancellable: false,
    },
    async () => deps.intel.verify(ref!, { force: options.force }),
  );

  deps.state.lastPackageReport = report;
  deps.dashboard.refresh();
  deps.reports.show(report);
  logReport(deps, report);

  const shouldNotify =
    options.notify === true ||
    (options.notify !== false && (!options.install || report.assessment.verdict === "block"));
  if (shouldNotify) {
    await notifyResult(report);
  }

  if (options.install) {
    await maybeInstall(deps, report);
  }
  return report;
}

async function promptForPackage(): Promise<string | undefined> {
  const clipboard = await clipboardCandidate();
  const value = await vscode.window.showInputBox({
    title: "Aegis · 依赖包安全核验",
    prompt:
      "输入包名或 install 命令。Aegis 会核对官方 registry、下载量、Stars、OSV 漏洞与相似包。",
    placeHolder: "npm install lodash   /   pip install requests",
    value: clipboard ?? "",
    ignoreFocusOut: true,
    validateInput: (input) => {
      if (!input.trim()) {
        return "请输入包名或 install 命令。";
      }
      try {
        parsePackageInput(input);
        return undefined;
      } catch (error) {
        return error instanceof Error ? error.message : "无法解析输入。";
      }
    },
  });
  return value?.trim() || undefined;
}

async function clipboardCandidate(): Promise<string | undefined> {
  try {
    const text = (await vscode.env.clipboard.readText()).trim();
    if (
      text.length > 0 &&
      text.length < 300 &&
      /^(npm|pnpm|yarn|bun)\s+(i|install|add|ci)\b/i.test(text)
    ) {
      return text;
    }
    if (
      text.length > 0 &&
      text.length < 300 &&
      /^(pip3?|python3?|uv|poetry|pdm)\b.*\b(install|add)\b/i.test(text)
    ) {
      return text;
    }
  } catch {
    // Clipboard access can fail in remote environments; not fatal.
  }
  return undefined;
}

async function notifyResult(report: PackageReport): Promise<void> {
  const name = report.ref.name;
  if (report.assessment.verdict === "block") {
    const action = await vscode.window.showErrorMessage(
      `Aegis 已阻断 ${name}：${report.assessment.headline}`,
      "查看报告",
    );
    if (action) {
      await vscode.commands.executeCommand("aegis.openReport", "package");
    }
  } else if (report.assessment.verdict === "review") {
    const action = await vscode.window.showWarningMessage(
      `Aegis 建议复核 ${name}：${report.assessment.headline}`,
      "查看报告",
    );
    if (action) {
      await vscode.commands.executeCommand("aegis.openReport", "package");
    }
  } else {
    void vscode.window.showInformationMessage(
      `Aegis 核验通过：${name}（风险分 ${report.assessment.score}）`,
    );
  }
}

async function maybeInstall(deps: AegisDeps, report: PackageReport): Promise<void> {
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage("Aegis: 当前处于受限模式，拒绝在工作区执行安装命令。");
    return;
  }

  if (report.assessment.verdict === "block") {
    return;
  }

  let shouldInstall = report.assessment.verdict === "allow";
  if (!shouldInstall) {
    const action = await vscode.window.showWarningMessage(
      `Aegis 未能完全确认 ${report.ref.name} 的安全性（风险分 ${report.assessment.score}）。仍要安装吗？`,
      { modal: true },
      "仍然安装",
      "查看报告",
    );
    if (action === "查看报告") {
      await vscode.commands.executeCommand("aegis.openReport", "package");
      return;
    }
    if (action !== "仍然安装") {
      return;
    }
    shouldInstall = true;
  }

  if (!shouldInstall) {
    return;
  }

  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri;
  const terminal = vscode.window.createTerminal({
    name: "Aegis Safe Install",
    cwd,
  });
  terminal.show(true);
  terminal.sendText(report.ref.installCommand, true);
  deps.output.appendLine(`[install] ${report.ref.installCommand}`);
  void vscode.window.showInformationMessage(
    `Aegis 已通过核验，正在终端执行：${report.ref.installCommand}`,
  );
}

export async function copyInstallCommand(deps: AegisDeps): Promise<void> {
  const report = deps.state.lastPackageReport;
  if (!report) {
    void vscode.window.showInformationMessage("Aegis: 暂无依赖核验结果。");
    return;
  }
  if (report.assessment.verdict === "block") {
    void vscode.window.showWarningMessage("Aegis: 该包已被阻断，不提供安装命令。");
    return;
  }
  await vscode.env.clipboard.writeText(report.ref.installCommand);
  void vscode.window.showInformationMessage(`已复制：${report.ref.installCommand}`);
}

export async function openRegistry(deps: AegisDeps): Promise<void> {
  const report = deps.state.lastPackageReport;
  if (!report?.facts.registryUrl) {
    return;
  }
  const uri = vscode.Uri.parse(report.facts.registryUrl);
  if (uri.scheme !== "https" && uri.scheme !== "http") {
    void vscode.window.showWarningMessage("Aegis: registry 地址不是 HTTP(S)，已拒绝打开。");
    return;
  }
  await vscode.env.openExternal(uri);
}

export async function recheckPackage(deps: AegisDeps): Promise<void> {
  const last = deps.state.lastPackageReport;
  if (!last) {
    void vscode.window.showInformationMessage("Aegis: 暂无依赖核验结果。");
    return;
  }
  await verifyPackageInteractive(deps, { ref: last.ref, force: true, notify: false });
}

export function logReport(deps: AegisDeps, report: PackageReport): void {
  deps.output.appendLine(
    `[package] ${report.ref.ecosystem}:${report.ref.name}@${report.ref.versionSpec ?? "latest"} ` +
      `=> ${report.assessment.verdict} (${report.assessment.score}) in ${report.durationMs}ms`,
  );
  for (const evidence of report.assessment.evidence) {
    deps.output.appendLine(`  - [${evidence.severity}] ${evidence.title}: ${evidence.detail}`);
  }
  for (const source of report.sources) {
    deps.output.appendLine(`  source ${source.name}: ${source.status} ${source.detail ?? ""}`);
  }
}
