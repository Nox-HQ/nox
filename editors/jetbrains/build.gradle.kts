// nox JetBrains plugin — a thin LSP client over `nox lsp`.
//
// The plugin uses the IntelliJ Platform LSP API (com.intellij.platform.lsp),
// available in paid JetBrains IDEs (IntelliJ IDEA Ultimate, PyCharm
// Professional, GoLand, WebStorm, etc.) from 2023.2 onward. For the free
// Community editions, install the LSP4IJ plugin and point it at `nox lsp`
// (see README).
plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "1.9.24"
    id("org.jetbrains.intellij") version "1.17.4"
}

group = "dev.nox"
version = "1.6.0"

repositories {
    mavenCentral()
}

// Target GoLand as the base IDE: it ships the platform LSP API and is a natural
// home for scanning Go/AI projects. The plugin also loads in IDEA Ultimate,
// PyCharm Professional, WebStorm, etc.
intellij {
    version.set("2024.1")
    type.set("GO")
    plugins.set(listOf())
}

tasks {
    withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        kotlinOptions.jvmTarget = "17"
    }
    patchPluginXml {
        sinceBuild.set("232") // 2023.2 — first release with the platform LSP API
        untilBuild.set("")
    }
}
