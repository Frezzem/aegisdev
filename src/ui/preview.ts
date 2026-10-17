import * as vscode from "vscode";

export class PreviewProvider implements vscode.TextDocumentContentProvider {
  private readonly contents = new Map<string, string>();

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.contents.get(uri.toString()) ?? "";
  }

  createUri(name: string): vscode.Uri {
    return vscode.Uri.from({
      scheme: "aegis-preview",
      path: `/${name.replace(/[\\/]/g, "_")}`,
      query: String(Date.now()),
    });
  }

  set(uri: vscode.Uri, content: string): void {
    this.contents.set(uri.toString(), content);
  }
}
