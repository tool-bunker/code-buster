# Homepage terminal recordings

These Terminalizer source files produce the animated terminal demonstrations on
the Code Buster homepage:

- `repository-overview.yml` renders `website/assets/repository-overview.gif`.
- `quality-workflow.yml` renders `website/assets/quality-workflow.gif`.

The YAML files contain both the captured terminal frames and all rendering
settings: terminal dimensions, font, colors, frame style, typing delays, output
pauses, and loop behavior. They use a generic `$` prompt and contain no local
absolute paths.

## Render

```sh
tool/website-recordings/render.sh
```

The script uses `npx` to run Terminalizer and overwrites the GIF files under
`website/assets/`.

## Refresh the captures
```sh
terminalizer record recording-name
```

