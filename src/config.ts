import * as vscode from "vscode";
import type { IntelOptions } from "./core/intel.js";

export interface ScanSettings {
  scanOnOpen: boolean;
  scanOnSave: boolean;
  maxScanFiles: number;
}

export function readIntelOptions(): IntelOptions {
  const cfg = vscode.workspace.getConfiguration("aegis");
  return {
    timeoutMs: clamp(cfg.get<number>("requestTimeoutMs", 2000), 500, 10_000),
    githubToken: cleanString(cfg.get<string>("githubToken", "")) || undefined,
    npmRegistry:
      cleanString(cfg.get<string>("npmRegistry", "https://registry.npmjs.org")) ||
      "https://registry.npmjs.org",
    policy: {
      minWeeklyDownloads: clamp(cfg.get<number>("minWeeklyDownloads", 100), 0, 1_000_000),
      typosquatGuard: cfg.get<boolean>("typosquatGuard", true),
      allowlist: stringArray(cfg.get<unknown>("allowlist", [])),
      blocklist: stringArray(cfg.get<unknown>("blocklist", [])),
    },
  };
}

export function readScanSettings(): ScanSettings {
  const cfg = vscode.workspace.getConfiguration("aegis");
  return {
    scanOnOpen: cfg.get<boolean>("scanOnOpen", true),
    scanOnSave: cfg.get<boolean>("scanOnSave", true),
    maxScanFiles: clamp(cfg.get<number>("maxScanFiles", 300), 10, 2000),
  };
}

const AGENT_FILE_RE =
  /(^|[\\/])(\.mcp\.json|[^\\/]+\.mcp\.json|\.cursorrules|\.clinerules|\.windsurfrules|\.aider\.conf\.yml|CLAUDE\.md|AGENTS\.md)$/i;

const AGENT_DIR_RE =
  /(^|[\\/])(\.cursor|\.claude|\.vscode|\.github|\.devcontainer|\.continue|\.codeium)([\\/]|$)/i;

export function isAgentConfigPath(fsPath: string): boolean {
  return AGENT_FILE_RE.test(fsPath) || AGENT_DIR_RE.test(fsPath);
}

export const AGENT_CONFIG_GLOBS = [
  "**/{.mcp.json,*.mcp.json,.cursorrules,.clinerules,.windsurfrules,.aider.conf.yml,CLAUDE.md,AGENTS.md}",
  "**/{.cursor,.claude,.vscode,.github,.devcontainer,.continue,.codeium}/**/*.{json,jsonc,yml,yaml,md,toml,mdc}",
  "**/.claude/**/*",
];

export const SCAN_EXCLUDE_GLOB =
  "**/{node_modules,.git,dist,out,build,vendor,.venv,venv,.next,.cache,.turbo,coverage}/**";

function cleanString(value: string | undefined): string {
  return (value ?? "").trim();
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.round(value)));
}
