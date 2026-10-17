import * as vscode from "vscode";
import type { ScanReport } from "../core/types.js";

export class StatusController implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.name = "AegisDev";
    this.item.command = {
      command: "aegis.openDashboard",
      title: "打开 Aegis 安全面板",
    };
    this.item.text = "$(shield) Aegis · 本地防护";
    this.item.tooltip = "AegisDev：依赖包核验与 Agent 配置隐藏字符扫描";
    this.item.show();
  }

  setScan(report: ScanReport): void {
    this.item.backgroundColor = undefined;
    if (report.verdict === "critical") {
      this.item.text = `$(shield) Aegis · ${report.counts.critical} 严重`;
      this.item.tooltip = `${report.headline}\n点击查看扫描报告`;
      this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
      this.item.command = {
        command: "aegis.openReport",
        title: "查看扫描报告",
        arguments: ["scan"],
      };
    } else if (report.verdict === "review") {
      this.item.text =
        report.findings.length > 0
          ? `$(shield) Aegis · ${report.findings.length} 风险`
          : `$(shield) Aegis · ${report.skippedFiles} 文件跳过`;
      this.item.tooltip = `${report.headline}\n点击查看扫描报告`;
      this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
      this.item.command = {
        command: "aegis.openReport",
        title: "查看扫描报告",
        arguments: ["scan"],
      };
    } else {
      this.item.text = "$(shield) Aegis · 配置干净";
      this.item.tooltip = `${report.headline}\n已扫描 ${report.filesScanned} 个文件`;
      this.item.command = {
        command: "aegis.openReport",
        title: "查看扫描报告",
        arguments: ["scan"],
      };
    }
  }

  reset(): void {
    this.item.backgroundColor = undefined;
    this.item.text = "$(shield) Aegis · 本地防护";
    this.item.tooltip = "AegisDev：依赖包核验与 Agent 配置隐藏字符扫描";
    this.item.command = {
      command: "aegis.openDashboard",
      title: "打开 Aegis 安全面板",
    };
  }

  dispose(): void {
    this.item.dispose();
  }
}
