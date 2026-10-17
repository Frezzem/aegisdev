import type * as vscode from "vscode";
import type { PackageIntelService } from "./core/intel.js";
import type { AegisState } from "./state.js";
import type { DashboardProvider } from "./ui/dashboard.js";
import type { PreviewProvider } from "./ui/preview.js";
import type { ReportPanel } from "./ui/reportPanel.js";
import type { StatusController } from "./ui/status.js";

export interface AegisDeps {
  context: vscode.ExtensionContext;
  intel: PackageIntelService;
  state: AegisState;
  reports: ReportPanel;
  dashboard: DashboardProvider;
  status: StatusController;
  diagnostics: vscode.DiagnosticCollection;
  previews: PreviewProvider;
  output: vscode.OutputChannel;
  version: string;
}
