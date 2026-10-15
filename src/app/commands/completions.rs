const COMMANDS: &str = "summary graph dead duplication structure clusters complexity flags hotspots inspect related why path score quality plan actions review pr doctor preview explain rules config baseline fix init test version update completions";

pub fn execute(shell: &str) {
    let output = match shell {
        "fish" => format!(
            "complete -c cb -f -a \"{COMMANDS}\"\n\
             complete -c cb -l root -r\n\
             complete -c cb -l lang -r\n\
             complete -c cb -l cache-dir -r\n\
             complete -c cb -l cache\n\
             complete -c cb -l format -a \"text json ndjson markdown sarif junit mermaid\""
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
             '--cache-dir[cache directory]:dir:_files -/' \
             '--format[format]:(text json ndjson markdown sarif junit mermaid)'"
        ),
        _ => format!("complete -W \"{COMMANDS}\" cb"),
    };
    println!("{output}");
}
