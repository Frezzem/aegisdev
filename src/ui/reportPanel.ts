import { randomBytes } from "node:crypto";
import * as vscode from "vscode";
import type { PackageReport, ScanReport } from "../core/types.js";
import { renderReportHtml } from "./templates.js";

export interface ReportAction {
  type: string;
  id?: string;
  file?: string;
}

export class ReportPanel implements vscode.Disposable {
  private panel?: vscode.WebviewPanel;
  private panelDisposables: vscode.Disposable[] = [];
  private readonly actionEmitter = new vscode.EventEmitter<ReportAction>();
  private current?: PackageReport | ScanReport;
  private closed = false;
  private disposed = false;

  readonly onDidAction = this.actionEmitter.event;

  constructor(
    private readonly extensionUri: vscode.Uri,
    private readonly version: string,
  ) {}

  show(report: PackageReport | ScanReport): void {
    if (this.disposed) {
      return;
    }
    this.ensurePanel();
    const panel = this.panel;
    if (!panel) {
      return;
    }
    this.current = report;
    panel.title =
      report.kind === "package"
        ? `AegisDev · ${report.ref.name}`
        : "AegisDev · Agent 配置扫描";
    panel.webview.html = renderReportHtml(report, {
      nonce: randomBytes(16).toString("hex"),
      cspSource: panel.webview.cspSource,
      version: this.version,
    });
    panel.reveal(undefined, true);
    this.closed = false;
  }

  update(report: PackageReport | ScanReport): void {
    if (!this.current || this.disposed) {
      return;
    }
    this.show(report);
  }

  isShowing(kind: "package" | "scan"): boolean {
    return this.current?.kind === kind && this.panel?.visible === true && !this.closed;
  }

  get currentKind(): "package" | "scan" | undefined {
    return this.current?.kind;
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.actionEmitter.dispose();
    this.closePanel();
  }

  private ensurePanel(): void {
    if (this.panel && !this.closed) {
      return;
    }
    this.closePanel();

    const panel = vscode.window.createWebviewPanel(
      "aegis.report",
      "AegisDev · 安全报告",
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [this.extensionUri],
      },
    );

    this.panelDisposables = [
      panel.webview.onDidReceiveMessage((message: unknown) => {
        if (!message || typeof message !== "object") {
          return;
        }
        const action = message as Record<string, unknown>;
        if (typeof action.type !== "string" || action.type.length > 40) {
          return;
        }
        this.actionEmitter.fire({
          type: action.type,
          id: typeof action.id === "string" ? action.id.slice(0, 300) : undefined,
          file: typeof action.file === "string" ? action.file.slice(0, 1000) : undefined,
        });
      }),
      panel.onDidDispose(() => {
        this.closed = true;
        this.closePanel();
      }),
    ];
    this.panel = panel;
    this.closed = false;
  }

  private closePanel(): void {
    for (const disposable of this.panelDisposables) {
      disposable.dispose();
    }
    this.panelDisposables = [];
    const panel = this.panel;
    this.panel = undefined;
    if (panel) {
      panel.dispose();
    }
  }
}
