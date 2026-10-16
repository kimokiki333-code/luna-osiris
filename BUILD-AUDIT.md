# NADIR build audit

This file records the release checks performed on the NADIR master tree.

## Baseline

- Source archive inspected: `osiris-master.zip`
- Original archive: ~10.5 MB compressed, 956 archived files in the inspected source snapshot.
- The deployment tree intentionally excludes installed dependencies (`node_modules`), Python caches, and local scratch/run artifacts.
- The application source remains a full Next.js 16 / React 19 / MapLibre application with its API routes, data layers, security guards, tests, Docker support, and optional intelligence service.

## Release cleanup

- Removed exact duplicate unused assets: `public/icon-192.png`, `public/osiris-icon.png`, and the unused duplicate submarine-cable dataset.
- Removed `scratch/` and `runs/` from the release tree. They are development/history artifacts rather than runtime dependencies; `scratch/` also contained an operational cache-injection document with private infrastructure details and therefore does not belong in a distributable master.
- Preserved `intel/`, `nginx/`, Docker files, docs, generated CCTV catalogues, and runtime data because they are part of the supported self-hosting architecture.

## Product / UX pass

- NADIR branding is applied to user-facing metadata, documentation, privacy pages, share text, AI system prompts, and interface copy while preserving legacy `OSIRIS_*` environment contracts and repository paths where changing them would break existing deployments.
- Reworked the web-app manifest metadata and icon declarations.
- Replaced the malformed/mislabelled social preview asset with a real 1200×630 PNG designed for NADIR.
- Removed the blanket `* { transition: ... }` rule. Map-heavy interfaces should not animate every DOM node whenever a theme/layer value changes; interactive components retain explicit transitions.
- Reduced the artificial splash ceiling from 7 seconds to 4.5 seconds and made the handoff depend more closely on the map becoming usable.
- Split several heavy secondary panels out of the dashboard entry path with `next/dynamic` so the first-load path prioritizes the globe, primary HUD, and search instead of eagerly importing large alert/remote/ArcGIS/markets/flight/navigation modules.

## Automated checks

- `tools/preflight.mjs`: PASS, 0 warnings.
- TypeScript/TSX syntax transpilation: PASS across 288 source files.
- Manifest JSON parsing: PASS.
- Public social preview asset: PASS, 1200×630 PNG.
- Dependency declaration vs lockfile presence: PASS; all declared dependencies are represented in `package-lock.json`.
- Final release archive: 443 files, ~2.9 MB compressed; installed dependencies are intentionally excluded.

## Additional findings

- The original social preview file was not merely misnamed: it was a 1024×1024 JPEG stored as `og-image.png`. It is now a genuine 1200×630 PNG matching the metadata contract.
- `public/site.webmanifest` was previously effectively blank (`name`/`short_name` empty and white theme). It now matches the NADIR manifest contract.
- A README badge pointed to `osirislive.app`; current verified public deployment is `osirisai.live`, so the badge link was corrected.
- Legacy `OSIRIS_*` environment names remain deliberately for compatibility; they are runtime contracts, not forgotten branding.

## Full build/test limitation

A clean `npm ci` was attempted against the locked dependency tree. The container transport timed out before installation completed; the subsequent offline attempt showed at least one package tarball was not cached. Therefore this audit does **not** claim that `npm run build` or the Vitest suite completed in this environment.

That limitation is intentional and explicit. The source tree has been syntax-checked and preflighted, but the final deployment gate is still a clean dependency install followed by `npm run build`, `npm run lint`, and `npm test` on a networked Node environment.
