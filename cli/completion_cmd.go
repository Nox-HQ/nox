package main

import (
	"fmt"
	"os"
)

func runCompletion(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox completion <bash|zsh|fish|powershell>") // nox:ignore AI-006 -- CLI usage text
		return 2
	}

	shell := args[0]
	switch shell {
	case "bash":
		fmt.Print(bashCompletion) // nox:ignore AI-006 -- shell completion script
	case "zsh":
		fmt.Print(zshCompletion) // nox:ignore AI-006 -- shell completion script
	case "fish":
		fmt.Print(fishCompletion) // nox:ignore AI-006 -- shell completion script
	case "powershell":
		fmt.Print(powershellCompletion) // nox:ignore AI-006 -- shell completion script
	default:
		fmt.Fprintf(os.Stderr, "unsupported shell: %s\n", shell)
		fmt.Fprintln(os.Stderr, "Supported shells: bash, zsh, fish, powershell")
		return 2
	}

	return 0
}

const bashCompletion = `# nox bash completion
_nox_completions() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="scan show explain badge serve registry plugin version baseline diff watch protect completion annotate"

    case "${prev}" in
        nox)
            COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
            return 0
            ;;
        --format)
            COMPREPLY=( $(compgen -W "json sarif cdx spdx all" -- "${cur}") )
            return 0
            ;;
        baseline)
            COMPREPLY=( $(compgen -W "write update show" -- "${cur}") )
            return 0
            ;;
        protect)
            COMPREPLY=( $(compgen -W "install uninstall status" -- "${cur}") )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "${cur}") )
            return 0
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "--format --output --quiet --verbose --version --json --base --head --debounce" -- "${cur}") )
        return 0
    fi

    COMPREPLY=( $(compgen -d -- "${cur}") )
}
complete -F _nox_completions nox
`

const zshCompletion = `#compdef nox
# nox zsh completion

_nox() {
    local -a commands
    commands=(
        'scan:Scan a directory for security issues'
        'show:Inspect findings interactively'
        'explain:Explain findings using an LLM'
        'badge:Generate an SVG status badge'
        'serve:Start MCP server on stdio'
        'registry:Manage plugin registries'
        'plugin:Manage and invoke plugins'
        'version:Print version and exit'
        'baseline:Manage finding baselines'
        'diff:Show findings in changed files'
        'watch:Watch for changes and re-scan'
        'completion:Generate shell completions'
        'protect:Manage git pre-commit hook'
        'annotate:Annotate a PR with findings'
    )

    _arguments -C \
        '--format[Output format]:format:(json sarif cdx spdx all)' \
        '--output[Output directory]:directory:_files -/' \
        '(-q --quiet)'{-q,--quiet}'[Suppress output]' \
        '(-v --verbose)'{-v,--verbose}'[Verbose output]' \
        '--version[Print version]' \
        '1:command:->cmds' \
        '*::arg:->args'

    case "$state" in
        cmds)
            _describe 'command' commands
            ;;
        args)
            case "${words[1]}" in
                scan|show|explain|badge|diff|watch)
                    _files -/
                    ;;
                baseline)
                    _values 'subcommand' write update show
                    ;;
                protect)
                    _values 'subcommand' install uninstall status
                    ;;
                completion)
                    _values 'shell' bash zsh fish powershell
                    ;;
            esac
            ;;
    esac
}

_nox "$@"
`

const fishCompletion = `# nox fish completion
complete -c nox -n '__fish_use_subcommand' -a 'scan' -d 'Scan a directory for security issues'
complete -c nox -n '__fish_use_subcommand' -a 'show' -d 'Inspect findings interactively'
complete -c nox -n '__fish_use_subcommand' -a 'explain' -d 'Explain findings using an LLM'
complete -c nox -n '__fish_use_subcommand' -a 'badge' -d 'Generate an SVG status badge'
complete -c nox -n '__fish_use_subcommand' -a 'serve' -d 'Start MCP server on stdio'
complete -c nox -n '__fish_use_subcommand' -a 'registry' -d 'Manage plugin registries'
complete -c nox -n '__fish_use_subcommand' -a 'plugin' -d 'Manage and invoke plugins'
complete -c nox -n '__fish_use_subcommand' -a 'version' -d 'Print version and exit'
complete -c nox -n '__fish_use_subcommand' -a 'baseline' -d 'Manage finding baselines'
complete -c nox -n '__fish_use_subcommand' -a 'diff' -d 'Show findings in changed files'
complete -c nox -n '__fish_use_subcommand' -a 'watch' -d 'Watch for changes and re-scan'
complete -c nox -n '__fish_use_subcommand' -a 'completion' -d 'Generate shell completions'
complete -c nox -n '__fish_use_subcommand' -a 'protect' -d 'Manage git pre-commit hook'
complete -c nox -n '__fish_use_subcommand' -a 'annotate' -d 'Annotate a PR with findings'
complete -c nox -l format -d 'Output format' -a 'json sarif cdx spdx all'
complete -c nox -l output -d 'Output directory' -rF
complete -c nox -s q -l quiet -d 'Suppress output'
complete -c nox -s v -l verbose -d 'Verbose output'
complete -c nox -l version -d 'Print version'
complete -c nox -n '__fish_seen_subcommand_from baseline' -a 'write update show'
complete -c nox -n '__fish_seen_subcommand_from protect' -a 'install uninstall status'
complete -c nox -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish powershell'
`

const powershellCompletion = `# nox PowerShell completion
Register-ArgumentCompleter -CommandName nox -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = @('scan', 'show', 'explain', 'badge', 'serve', 'registry', 'plugin', 'version', 'baseline', 'diff', 'watch', 'protect', 'completion', 'annotate')

    $commands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
`
