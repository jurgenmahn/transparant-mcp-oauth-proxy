# Repository Guidelines

## Project Structure & Module Organization
- `app/`: Node.js server (`server.js`), `services/` (dashboard, proxy, OAuth), `config/` (`local.yaml`), `templates/`, and runtime deps.
- `conf/`: OAuth2 (Hydra) config under `etc/hydra/` and startup scripts in `scripts/`.
- `static/`: Client assets (e.g., CSS) used by the dashboard.
- Root: `Dockerfile`, `README.md`, helper scripts (`debug-yaml-path.js`, `test-fix.js`).

## Build, Test, and Development Commands
- Local run (Node ≥ 20): `cd app && npm ci && npm run dev`
  - Starts the MCP launcher at port from `app/config/local.yaml` (`server_port`, default 3000).
- Start without reinstall: `node app/server.js`
- Docker build/run: `docker build -t mcp-launcher .` then `docker run -p 3000:3000 mcp-launcher`
- Quick health check: `curl http://localhost:3000/health`
- SSE check: `curl -H "Accept: text/event-stream" http://localhost:3000/sse`
- Config debugging: `node debug-yaml-path.js` and `node test-fix.js`

## Coding Style & Naming Conventions
- ES Modules (`type: module`), 2-space indentation, semicolons, single quotes or consistent quoting.
- Filenames: kebab-case (`dashboard-service.js`, `launcher-proxy-service.js`). Classes in PascalCase.
- Functions/variables: camelCase; constants: UPPER_SNAKE_CASE.
- Keep configuration-driven behavior; read from YAML and `this.appPath`. Avoid hardcoded absolute paths.

## Testing Guidelines
- No formal unit test suite. Prefer integration checks via endpoints and the dashboard.
- Use curl examples above; validate tool registration on `/` JSON-RPC and SSE stream.
- For config changes, run `debug-yaml-path.js` to verify nested YAML paths update as expected.

## Commit & Pull Request Guidelines
- Commits: concise, imperative, scoped (e.g., "feat: add hydra field mapping", "fix: handle SSE disconnects").
- PRs: include summary, motivation, linked issues, and testing notes (health/SSE outputs). Add screenshots for dashboard UI changes.
- Update docs (`README.md`, `AGENTS.md`) when changing config shape, routes, or startup instructions.

## Security & Configuration Tips
- Do not commit real secrets to `app/config/local.yaml` (e.g., `session_secret`). Use placeholders.
- Restrict `oauth.allowed_redirect_domains` and CORS origins to trusted domains.
- Be cautious with `mcp_services.startup_command`; validate inputs and avoid shell injection.
- If Hydra settings change, note services needing restart and provide commands in the PR description.

