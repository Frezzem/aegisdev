import * as vscode from "vscode";

export class AegisCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const diagnostics = context.diagnostics.filter(
      (diagnostic) => diagnostic.source === "AegisDev" && diagnostic.code === "hidden-unicode",
    );
    if (diagnostics.length === 0) {
      return [];
    }

    const fixFile = new vscode.CodeAction(
      "Aegis: 净化此文件中的隐藏字符",
      vscode.CodeActionKind.QuickFix,
    );
    fixFile.diagnostics = diagnostics;
    fixFile.command = {
      command: "aegis.sanitizeFile",
      title: "净化此文件",
      arguments: [document.uri],
    };
    fixFile.isPreferred = true;

    const preview = new vscode.CodeAction(
      "Aegis: 预览净化结果",
      vscode.CodeActionKind.QuickFix,
    );
    preview.diagnostics = diagnostics;
    preview.command = {
      command: "aegis.previewSanitized",
      title: "预览净化结果",
      arguments: [document.uri],
    };

    return [fixFile, preview];
  }
}
