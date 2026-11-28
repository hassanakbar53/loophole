# Bash completion for loophole (https://github.com/rootsiemen/loophole).
#
# Install: copy this file into your bash-completion directory, then
# start a new shell (or `source` it for the current session only):
#
#   cp completions/loophole.bash ~/.local/share/bash-completion/completions/loophole
#
# Completes the `scan` subcommand, every `scan` flag, the `--severity`
# choices, file paths for the report/config options, rule IDs for
# `--explain`, and files/directories for the scan target.
# See README.md ("Shell completions").
_loophole() {
    local cur prev sub
    local -a flags=(
        -h --help
        --json --sarif --format --annotations --fix-dry --severity --exclude --no-color
        --config --baseline --write-baseline --html --junit --gitlab --cache
        --rules --explain
    )
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Complete a value after `--flag=value` (e.g. --severity=cr<TAB>).
    if [[ "$cur" == --*=* ]]; then
        local flag="${cur%%=*}"
        local val="${cur#*=}"
        case "$flag" in
            --severity)
                COMPREPLY=( $(compgen -W "critical high medium" -- "$val") )
                ;;
            --format)
                COMPREPLY=( $(compgen -W "text annotations" -- "$val") )
                ;;
            --json|--sarif|--config|--baseline|--write-baseline|--html|--junit|--gitlab|--cache)
                COMPREPLY=( $(compgen -f -- "$val") )
                ;;
        esac
        return 0
    fi

    # Find the subcommand: the first non-flag word after `loophole`.
    sub=""
    local i
    for (( i=1; i < COMP_CWORD; i++ )); do
        case "${COMP_WORDS[i]}" in
            -*) ;;
            *) sub="${COMP_WORDS[i]}"; break ;;
        esac
    done

    # No subcommand yet: complete `scan` (and -h/--help).
    if [[ -z "$sub" ]]; then
        COMPREPLY=( $(compgen -W "scan -h --help" -- "$cur") )
        return 0
    fi

    case "$sub" in
        scan)
            # Complete the value of the previous flag.
            case "$prev" in
                --severity)
                    COMPREPLY=( $(compgen -W "critical high medium" -- "$cur") )
                    return 0
                    ;;
                --format)
                    COMPREPLY=( $(compgen -W "text annotations" -- "$cur") )
                    return 0
                    ;;
                --json|--sarif|--config|--baseline|--write-baseline|--html|--junit|--gitlab|--cache)
                    COMPREPLY=( $(compgen -f -- "$cur") )
                    return 0
                    ;;
                --exclude)
                    COMPREPLY=( $(compgen -d -- "$cur") )
                    return 0
                    ;;
                --explain)
                    local -a ids=()
                    if command -v loophole >/dev/null 2>&1; then
                        mapfile -t ids < <(loophole scan --rules . 2>/dev/null | grep -oE '[A-Z]+[0-9]{3}' | sort -u)
                    fi
                    COMPREPLY=( $(compgen -W "${ids[*]}" -- "$cur") )
                    return 0
                    ;;
            esac
            # Complete flags, or the scan target (file or directory).
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "${flags[*]}" -- "$cur") )
            else
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi
            return 0
            ;;
    esac
}

complete -F _loophole loophole
