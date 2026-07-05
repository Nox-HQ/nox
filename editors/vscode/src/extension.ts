import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

// The languages nox scans; the client only forwards documents of these types to
// the server, so nox is invoked on files it understands.
const documentSelector: { scheme: string; language: string }[] = [
  "go",
  "python",
  "javascript",
  "javascriptreact",
  "typescript",
  "typescriptreact",
  "ruby",
  "java",
  "kotlin",
  "rust",
  "c",
  "cpp",
  "csharp",
  "php",
  "shellscript",
  "yaml",
  "json",
  "dockerfile",
].map((language) => ({ scheme: "file", language }));

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration("nox");
  if (!config.get<boolean>("enable", true)) {
    return;
  }

  // The server is `nox lsp` over stdio: deterministic, offline, no network.
  const command = config.get<string>("path", "nox");
  const serverOptions: ServerOptions = {
    run: { command, args: ["lsp"], transport: TransportKind.stdio },
    debug: { command, args: ["lsp"], transport: TransportKind.stdio },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector,
    diagnosticCollectionName: "nox",
  };

  client = new LanguageClient(
    "nox",
    "nox",
    serverOptions,
    clientOptions,
  );
  client.start();
  context.subscriptions.push({ dispose: () => void client?.stop() });
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}
