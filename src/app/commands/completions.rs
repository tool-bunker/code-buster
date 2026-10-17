const COMMANDS: &str = "summary review inspect graph dead duplication quality rules baseline fix init doctor config update completions version";

pub fn execute(shell: &str) {
    let output = match shell {
        "fish" => format!(
            "complete -c cb -f -a \"{COMMANDS}\"\n\
             complete -c cb -l root -r\n\
             complete -c cb -l lang -r\n\
             complete -c cb -l cache-dir -r\n\
             complete -c cb -l cache\n\
             complete -c cb -l profile\n\
             complete -c cb -l format -a \"text json ndjson markdown sarif junit mermaid plan actions\""
        ),
        "powershell" | "pwsh" => format!(
            "Register-ArgumentCompleter -Native -CommandName cb -ScriptBlock {{\n\
             \x20   param($wordToComplete, $commandAst, $cursorPosition)\n\
             \x20   '{COMMANDS}'.Split(' ') |\n\
             \x20       Where-Object {{ $_ -like \"$wordToComplete*\" }} |\n\
             \x20       ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }}\n\
             }}"
        ),
        "zsh" => format!(
            "#compdef cb\n_arguments '1:command:({COMMANDS})' \
             '--root[project root]:dir:_files -/' \
             '--lang[language]:' \
             '--cache[reuse analysis cache]' \
             '--profile[measure uncached rule-pack execution]' \
             '--cache-dir[cache directory]:dir:_files -/' \
             '--format[format]:(text json ndjson markdown sarif junit mermaid plan actions)'"
        ),
        _ => format!("complete -W \"{COMMANDS}\" cb"),
    };
    println!("{output}");
}
