# Rampart web

The Rampart UI: a static React single-page app. It holds no secrets; sign-in is a session cookie set by `query-api` (docs/14 section 2). Design rules are in docs/13 section 6 and docs/18.

## Prerequisites

Bun 1.4 or newer (the lockfile is `bun.lock`). Then `bun install`.

## Scripts

| Command | What it does |
|---|---|
| `bun run dev` | Vite dev server on http://127.0.0.1:5173, proxies `/api` and `/auth` |
| `bun run mock` | Mock backend on port 8099 (`dev/mock-server.mjs`) |
| `bun run build` | Typecheck, then build to `dist/` (hashed files under `/assets/`) |
| `bun run preview` | Serve `dist/` on port 4173 with the production CSP header |
| `bun run test` | Vitest, Testing Library and axe |
| `bun run typecheck` | `tsc --noEmit`, strict |
| `bun run lint` | ESLint |

## Run it against the mock server

```
bun run mock          # terminal 1
bun run dev           # terminal 2, open http://127.0.0.1:5173
```

Switch scenario while it runs: `curl 'http://127.0.0.1:5173/__mock/scenario?set=<name>'`, or start with `MOCK_SCENARIO=<name> bun run mock`.

| Scenario | Behaviour |
|---|---|
| `loggedout` | `GET /auth/session` answers 401. Signing in switches to the last data scenario |
| `empty` | Signed in, zero findings |
| `populated` | Signed in, 25 findings across all five bands (default) |
| `error` | Signed in, `GET /api/v1/findings` answers a 500 problem |

`MOCK_METHODS='[{"id":"a","name":"Okta","type":"oidc"},{"id":"b","name":"Entra","type":"oidc"}]'` shows the identity provider chooser. Signing in with tenant `nope` or `denied` redirects to `/login?error=...`. `/styleguide` (dev only) shows every base component.

## Run it against a real backend

```
RAMPART_BACKEND=http://127.0.0.1:8080 bun run dev
```

## How the build is served

`bun run build` writes `web/dist`. `dist/.keep` is committed so `//go:embed all:dist` compiles before the first build; the build recreates it. The Go server serves `dist` at `/` with `index.html` as `no-cache` and `/assets/*` as immutable, falls back to `index.html` for client routes, and sets `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`. The bundle has no inline script, no inline style attribute in markup and no external origin; fonts are self-hosted.

## Layout

`src/app` router, shell, bootstrap. `src/routes` screens. `src/features` filter bar, facets, findings table, inspector. `src/components` design-system primitives. `src/api` the only code that touches the network, plus the query-key factory. `src/lib` grammar, score maths, formatting, i18n (`lib/i18n/en.ts` holds every string). `src/styles` tokens and themes.

The API types are written by hand from the Go structs. `/api/v1/openapi.json` does not exist yet; when it does, generate types with openapi-typescript and replace the calls in `src/api/endpoints.ts` with openapi-fetch. Nothing outside `api/` changes.

## Troubleshooting

- Blank page, console shows a CSP violation: something injected inline style or script. Radix modal mode does this; use the wrappers in `src/components`.
- Login loops back to `/login`: the session cookie is not reaching the browser; check the dev proxy target and that the backend sets the cookie for the same origin.
