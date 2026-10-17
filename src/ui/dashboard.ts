import * as vscode from "vscode";
import type { Verdict } from "../core/types.js";
import type { AegisState } from "../state.js";

type NodeKind = "group" | "action" | "packageResult" | "scanResult" | "empty" | "status";

interface AegisNode {
  id: string;
  kind: NodeKind;
  label: string;
  description?: string;
  tooltip?: string;
  icon?: vscode.ThemeIcon;
  command?: vscode.Command;
  children?: AegisNode[];
  collapsible?: vscode.TreeItemCollapsibleState;
}

export class DashboardProvider implements vscode.TreeDataProvider<AegisNode> {
  private readonly changed = new vscode.EventEmitter<AegisNode | undefined>();
  readonly onDidChangeTreeData = this.changed.event;

  constructor(private readonly state: AegisState) {}

  refresh(): void {
    this.changed.fire(undefined);
  }

  getTreeItem(element: AegisNode): vscode.TreeItem {
    const item = new vscode.TreeItem(
      element.label,
      element.collapsible ??
        (element.children && element.children.length > 0
          ? vscode.TreeItemCollapsibleState.Expanded
          : vscode.TreeItemCollapsibleState.None),
    );
    item.id = element.id;
    item.description = element.description;
    item.tooltip = element.tooltip ?? element.description;
    item.iconPath = element.icon;
    item.command = element.command;
    item.contextValue = element.kind;
    return item;
  }

  getChildren(element?: AegisNode): AegisNode[] {
    if (!element) {
      return this.groups();
    }
    return element.children ?? [];
  }

  private groups(): AegisNode[] {
    return [this.actionsGroup(), this.resultsGroup(), this.statusGroup()];
  }

  private actionsGroup(): AegisNode {
    return {
      id: "group.actions",
      kind: "group",
      label: "安全操作",
      icon: new vscode.ThemeIcon("shield"),
      children: [
        action(
          "action.verify",
          "校验依赖包",
          "aegis.verifyPackage",
          "search",
          "查注册表、下载量、Stars、漏洞与相似包",
        ),
        action(
          "action.install",
          "校验并安全安装",
          "aegis.verifyAndInstall",
          "cloud-download",
          "先核验，通过后再把重建后的安装命令发送到终端",
        ),
        action(
          "action.scan",
          "扫描 Agent 配置",
          "aegis.scanAgentConfigs",
          "search-fuzzy",
          "检查 .mcp.json / .cursorrules / .claude 等文件中的隐藏字符",
        ),
        action(
          "action.scanFile",
          "扫描当前文件",
          "aegis.scanCurrentFile",
          "file-code",
          "仅扫描当前编辑器中的文件",
        ),
        action(
          "action.settings",
          "安全基线设置",
          "aegis.openSettings",
          "settings-gear",
          "配置白名单、超时与扫描范围",
        ),
      ],
    };
  }

  private resultsGroup(): AegisNode {
    const children: AegisNode[] = [];
    const pkg = this.state.lastPackageReport;
    if (pkg) {
      const verdict = pkg.assessment.verdict;
      children.push({
        id: "result.package",
        kind: "packageResult",
        label: pkg.ref.name,
        description: `${verdictLabel(verdict)} · ${pkg.assessment.score} 分`,
        tooltip: pkg.assessment.headline,
        icon: new vscode.ThemeIcon(
          verdictIcon(verdict),
          verdict === "allow"
            ? new vscode.ThemeColor("testing.iconPassed")
            : verdict === "review"
              ? new vscode.ThemeColor("editorWarning.foreground")
              : new vscode.ThemeColor("errorForeground"),
        ),
        command: {
          command: "aegis.openReport",
          title: "打开依赖核验报告",
          arguments: ["package"],
        },
      });
    }
    const scan = this.state.lastScan;
    if (scan) {
      children.push({
        id: "result.scan",
        kind: "scanResult",
        label: scan.scope === "file" ? "当前文件扫描" : "Agent 配置扫描",
        description:
          scan.filesWithFindings > 0
            ? `${scan.filesWithFindings} 个文件 · ${scan.counts.critical} 严重`
            : scan.skippedFiles > 0
              ? `${scan.skippedFiles} 个文件被跳过`
              : "未发现隐藏字符",
        tooltip: scan.headline,
        icon: new vscode.ThemeIcon(
          scan.verdict === "critical"
            ? "error"
            : scan.verdict === "review"
              ? "warning"
              : "pass",
          scan.verdict === "critical"
            ? new vscode.ThemeColor("errorForeground")
            : scan.verdict === "review"
              ? new vscode.ThemeColor("editorWarning.foreground")
              : new vscode.ThemeColor("testing.iconPassed"),
        ),
        command: {
          command: "aegis.openReport",
          title: "打开配置扫描报告",
          arguments: ["scan"],
        },
      });
    }
    if (children.length === 0) {
      children.push({
        id: "result.empty",
        kind: "empty",
        label: "暂无安全记录",
        description: "运行一次核验或扫描",
        icon: new vscode.ThemeIcon("history"),
      });
    }
    return {
      id: "group.results",
      kind: "group",
      label: "最近结果",
      icon: new vscode.ThemeIcon("pulse"),
      children,
    };
  }

  private statusGroup(): AegisNode {
    return {
      id: "group.status",
      kind: "group",
      label: "防护状态",
      icon: new vscode.ThemeIcon("lock"),
      children: [
        {
          id: "status.privacy",
          kind: "status",
          label: "隐私模式",
          description: "代码不出域",
          tooltip: "静态扫描与净化全部本地执行；核验仅发送包名等公开元数据。",
          icon: new vscode.ThemeIcon("eye-closed"),
        },
        {
          id: "status.sources",
          kind: "status",
          label: "核验数据源",
          description: "NPM · PyPI · OSV · GitHub",
          icon: new vscode.ThemeIcon("database"),
        },
        {
          id: "status.version",
          kind: "status",
          label: "版本",
          description: "V1.0 MVP",
          icon: new vscode.ThemeIcon("versions"),
        },
      ],
    };
  }
}

function action(
  id: string,
  label: string,
  command: string,
  icon: string,
  tooltip: string,
): AegisNode {
  return {
    id,
    kind: "action",
    label,
    tooltip,
    icon: new vscode.ThemeIcon(icon),
    command: { command, title: label },
  };
}

function verdictLabel(verdict: Verdict): string {
  return verdict === "allow" ? "可以安装" : verdict === "review" ? "需复核" : "已阻断";
}

function verdictIcon(verdict: Verdict): string {
  return verdict === "allow" ? "pass" : verdict === "review" ? "warning" : "error";
}
