import type * as vscode from "vscode";
import type { PackageReport, ScanReport } from "./core/types.js";

export class AegisState {
  lastPackageReport?: PackageReport;
  lastScan?: ScanReport;
  /** Display path -> real URI, used by report actions and diagnostics. */
  scanTargets = new Map<string, vscode.Uri>();
}
