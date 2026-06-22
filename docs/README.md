# ProveKit Docs Website

Standalone documentation website for ProveKit, built with Astro and Starlight.

The public docs are organized by task:

- **Start here:** installation, setup, and first proof.
- **Build and integrate:** end-to-end artifact generation and host-language integration paths.
- **Concepts:** proving flow, artifact lifecycle, and trust boundaries.
- **Reference:** CLI commands, versioning policy, glossary, and production readiness.
- **Troubleshooting:** failure diagnosis and recovery steps.

## Commands

```sh
cd docs
corepack enable
pnpm install
pnpm check
pnpm dev
pnpm build
```

Run `pnpm check` and `pnpm build` before publishing documentation changes.

## Content layout

Documentation source lives in `src/content/docs/`.

- `index.mdx` is the docs homepage.
- Section folders map to URL paths, for example `getting-started/quickstart.mdx` -> `/getting-started/quickstart/`.
- Sidebar structure is configured in `astro.config.mjs`.
- Custom theme polish lives in `src/styles/starlight.css`.
- Conceptual pages live under `concepts/`.
- Integration and end-to-end pages live under `e2e/` and `integrations/`.
- Reference pages live under `reference/`.
- Troubleshooting pages live under `troubleshooting/`.

The repository root `README.md` remains the project entry point for contributors and the CLI quick start.

## Writing standards

- Keep runnable commands copy-pasteable from a fresh checkout.
- Prefer explicit artifact paths in production and CI examples.
- State generated files, owners, and regeneration rules.
- Separate tutorials, how-to material, conceptual explanation, and reference content.
- Mark active-development caveats instead of implying stable guarantees.
- Link to source files or reference pages when a claim depends on implementation details.
