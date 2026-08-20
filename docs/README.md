# Code Buster documentation

Documentation for Code Buster.

## Development

Run commands from `code-buster/docs/`:

```sh
npm install
npm run dev
```

The local site is available at `http://localhost:4321` by default.

## Verification

```sh
npm run astro -- check
npm run build
```

Documentation pages live under `src/content/docs/`. Navigation is configured in `astro.config.mjs`.
