# Installation

Build and install the canonical Dart Code Buster CLI.

Code Buster requires Dart 3.11 or newer. The executable is named `cb`.

> [!CAUTION]
> **Pre-1.0 software:** Code Buster is under heavy development. It can already
> support local repository exploration and provide additional context to AI
> coding agents, but behavior and findings may change before version 1.0.0. Do
> not yet use it as a blocking quality gate in a production pipeline. Treat CI
> and report integrations as evaluation or non-blocking visibility.

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
