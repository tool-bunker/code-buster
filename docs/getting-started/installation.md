# Installation

Install a native Code Buster release or build the canonical Dart CLI from source.

Building from source requires Dart 3.11 or newer. Native packages do not require
the Dart SDK. The executable is named `cb`.

> [!CAUTION]
> **Pre-1.0 software:** Code Buster is under heavy development. It can already
> support local repository exploration and provide additional context to AI
> coding agents, but behavior and findings may change before version 1.0.0. Do
> not yet use it as a blocking quality gate in a production pipeline. Treat CI
> and report integrations as evaluation or non-blocking visibility.

## Homebrew

On Apple Silicon macOS:

```sh
brew install tool-bunker/tap/code-buster
cb version
```

Upgrade later with:

```sh
brew update
brew upgrade code-buster
```

## Install script

On Apple Silicon macOS or x86-64 Linux:

```sh
curl -fsSL https://codebuster.toolbunker.dev/install | sh
```

The script downloads the latest native release, verifies its SHA-256 checksum,
and installs `cb` under `${PREFIX:-$HOME/.local}/bin`.

To inspect the script before running it:

```sh
curl -fsSL https://codebuster.toolbunker.dev/install -o install-code-buster.sh
less install-code-buster.sh
sh install-code-buster.sh
```

## Windows

From PowerShell on x86-64 Windows:

```powershell
irm https://codebuster.toolbunker.dev/install.ps1 | iex
```

The script verifies the release checksum and installs `cb.exe` under
`$HOME\\.local\\bin`. Add that directory to `PATH` when the installer asks.

To inspect it before execution:

```powershell
Invoke-WebRequest https://codebuster.toolbunker.dev/install.ps1 -OutFile install-code-buster.ps1
Get-Content .\\install-code-buster.ps1
& .\\install-code-buster.ps1
```

## Build from source

Run these commands from the `code-buster/` directory:

```sh
dart pub get
dart compile exe bin/cb.dart -o build/cb
./build/cb version
```

The compiled executable is self-contained and can be copied to a directory on your `PATH`.

## Workspace installer

From the parent development workspace, run:

```sh
./install-code-buster.sh
```

The installer builds the current local source and installs `cb` under `~/.local/bin` by default. Select another prefix when needed:

```sh
PREFIX=/opt ./install-code-buster.sh
```

Ensure `$PREFIX/bin` is on `PATH`, then verify the installation:

```sh
cb version
```

## Run without compiling

During development, invoke the Dart entry point directly:

```sh
dart run bin/cb.dart version
```

Use the compiled executable for performance measurements and release evidence so startup behavior matches distributed builds.
