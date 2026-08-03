## What this is

Millennium Radius Portal — an internal application launcher / credential vault. It lists company
applications (Cognisense, Salesforce, Slack, Jira, etc.) with their login URL, username, and
password so staff can look up and copy credentials from one place. There are two surfaces: a
portal for end users and an admin console for managing the application list.

## Running

No dependencies, no build step, no package.json. Everything is a single Node.js process using only
built-in modules (`http`, `fs`, `path`, `url`).

```bash
node server.js
```

- Portal UI: `http://localhost:3000`
- Admin console: `http://localhost:3000/management.html`
- Configure port/passwords via env vars: `PORT`, `ADMIN_PASSWORD` (default `admin123`),
  `PORTAL_PASSWORD` (default `portal123`).

There are no tests, no linter, and no npm scripts configured in this repo.

## Architecture

**server.js** is a single-file HTTP server (no Express/framework) that does three jobs:
1. Serves the two HTML frontends as static files (`/` and `/frontend.html` → `frontend.html`,
   `/management.html` → `management.html`).
2. Serves `/data.json` as the read model for both frontends.
3. Exposes a small REST API under `/api/*` for auth and CRUD on applications.

**Data storage**: `data.json` is the entire database — a flat JSON array of application objects
(`id`, `name`, `icon`, `category`, `description`, `url`, `username`, `password`, `isActive`).
`readData()`/`writeData()` in server.js do synchronous full-file read/write on every request; there
is no database. Passwords are stored in plaintext.

**Sessions**: in-memory only (`sessions.admin` / `sessions.portal` objects in server.js), not
persisted — restarting the server invalidates all sessions. Session IDs are generated with
`Math.random().toString(36)`, not a CSPRNG. Sessions expire after 24h but expiry is only recorded
(`expiresAt`), not actively enforced against `Date.now()` in `isValidSession`.

**Two independent auth realms**, distinguished by a `type` param (`admin` | `portal`) threaded
through session functions and the `/api/auth/*` endpoints:
- Admin (`management.html`): password login → full CRUD on applications (`POST/PUT/DELETE
  /api/applications`), each write-endpoint checks `sessionId` as a query param against
  `sessions.admin`.
- Portal (`frontend.html`): password login → read-only browse/search of applications and a
  "reveal credentials" modal; does not call the write API.

Both HTML files keep their own client-side session state and mirror it into `localStorage`
(`sessionId` for admin, `portalSessionId` for portal) so a page reload restores login state via
`/api/auth/verify`.

**frontend-demo.html** is a standalone, backend-independent demo of the portal UI. It is not
routed by server.js at all — it seeds/reads from `localStorage['millenniumRadiusApps']` instead of
calling the API, so it works when opened directly as a static file with no server running. Treat it
as a separate artifact from `frontend.html`/`management.html`, not something server.js needs to
serve.

## Conventions when editing

- All three HTML files are self-contained (inline `<style>` and `<script>`, no bundler) — keep new
  frontend code inline rather than introducing a build step, unless asked.
- New API routes follow the existing pattern in server.js: a chain of `if (pathname === ... &&
  req.method === ...)` blocks ending in an early `return`, manual `req.on('data'/'end')` body
  buffering for POST/PUT, and `requireAuth(sessionId, type)` checks before any admin-only mutation.
- Application IDs are plain incrementing integers assigned by the client, not the server — when
  adding an application, callers must supply `id` themselves (see `management.html`'s
  `addApplication`).
