package dev.nox.lsp

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.platform.lsp.api.LspServerSupportProvider
import com.intellij.platform.lsp.api.ProjectWideLspServerDescriptor

// The languages nox scans. The client only starts the server for files of these
// types, so `nox lsp` is invoked on files it understands.
private val SUPPORTED_EXTENSIONS = setOf(
    "go", "py", "pyi",
    "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts",
    "rb", "java", "kt", "rs", "c", "cc", "cpp", "cs", "php",
    "sh", "bash", "yaml", "yml", "json", "tf", "dockerfile",
)

private fun isSupported(file: VirtualFile): Boolean {
    val ext = file.extension?.lowercase()
    if (ext != null && ext in SUPPORTED_EXTENSIONS) return true
    // Dockerfiles and a handful of agent-config files have no telling extension.
    return file.name.equals("Dockerfile", ignoreCase = true) ||
        file.name in setOf(".cursorrules", ".clinerules", ".windsurfrules",
            "CLAUDE.md", "AGENTS.md", "GEMINI.md", "mcp.json", "manifest.json", "agent.json")
}

/**
 * Registers the nox language server with the IntelliJ Platform LSP API. When a
 * supported file is opened, the platform starts (or reuses) one `nox lsp`
 * process per project and surfaces its diagnostics inline, in the Problems view,
 * and in the gutter. Deterministic and offline: it runs the local `nox` binary;
 * no code leaves the machine and no model is called.
 */
class NoxLspServerSupportProvider : LspServerSupportProvider {
    override fun fileOpened(
        project: Project,
        file: VirtualFile,
        serverStarter: LspServerSupportProvider.LspServerStarter,
    ) {
        if (isSupported(file)) {
            serverStarter.ensureServerStarted(NoxLspServerDescriptor(project))
        }
    }
}

private class NoxLspServerDescriptor(project: Project) :
    ProjectWideLspServerDescriptor(project, "nox") {

    override fun isSupportedFile(file: VirtualFile): Boolean = isSupported(file)

    // `nox lsp` speaks JSON-RPC 2.0 over stdio. The binary is resolved from the
    // PATH; override with the NOX_PATH environment variable if it lives
    // elsewhere.
    override fun createCommandLine(): GeneralCommandLine {
        val exe = System.getenv("NOX_PATH")?.takeIf { it.isNotBlank() } ?: "nox"
        return GeneralCommandLine(exe, "lsp")
    }
}
