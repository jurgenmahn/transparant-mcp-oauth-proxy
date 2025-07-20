# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP (Model Context Protocol) launcher that provides a bridge to multiple MCP services. It's designed to run as a containerized service that manages and proxies connections to various MCP servers including filesystem, memory, git, database, web scraping, and other tools.

## Architecture

### Main Implementation: Smart MCP Proxy SDK (`app/smart-mcp-proxy-sdk.js`)
- **Primary entry point** - A dynamic MCP bridge that auto-discovers tools from services
- Uses `@modelcontextprotocol/sdk` for MCP protocol handling
- Spawns child processes for each MCP service defined in `SERVICES`
- Dynamically registers tools from all services with prefixed names (e.g., `memory_read`, `git_status`)
- Supports both SSE (Server-Sent Events) and stdio transports
- Converts JSON Schema to Zod schemas for tool validation
- **Includes comprehensive debug logging** via `DebugLogger` class:
  - HTTP requests/responses (headers, body, status codes)
  - MCP JSON-RPC messages (requests → and responses ←)
  - Timestamped logging for troubleshooting

### Legacy Implementation
- `mcp-proxy/smart-mcp-proxy.js` - Old implementation, scheduled for deletion

## Common Development Commands

### Docker Operations
```bash
# Build the container
docker build -t mcp-launcher .

# Run the container
docker run -p 3000:3000 mcp-launcher

# Run with environment variables
docker run -p 3000:3000 -e NODE_ENV=production mcp-launcher
```

### NPM Scripts (from app/package.json)
```bash
# Start the main service (smart-mcp-proxy-sdk.js)
npm start

# Start individual MCP services (for testing)
npm run serve:claude
npm run serve:dbhub
npm run serve:fetch
npm run serve:filesystem
npm run serve:git
npm run serve:memory
npm run serve:playwright

# Legacy command (will be removed)
npm run smart-proxy
```

### Development Setup
```bash
# Install dependencies (skip puppeteer download if needed)
PUPPETEER_SKIP_DOWNLOAD=true npm install

# Start the service with debugging
NODE_ENV=development npm start

# Run from app directory
cd app && npm start
```

## Service Configuration

MCP services are configured in both proxy files through the `SERVICES` object:

- **memory**: `@modelcontextprotocol/server-memory`
- **filesystem**: `@modelcontextprotocol/server-filesystem` (workspace: `/workspace`)
- **git**: `@cyanheads/git-mcp-server`
- **fetch**: `@tokenizin/mcp-npx-fetch`
- **playwright**: `@executeautomation/playwright-mcp-server` (with --vision flag)
- **dbhub**: `@bytebase/dbhub` (MySQL connection to `192.168.113.2:3306/asp`)

## Port Configuration

The container exposes port 3000 for the main proxy service:
- Port 3000: Main proxy service (SSE and HTTP endpoints)
- SSE endpoint: `http://localhost:3000/sse`
- Health check: `http://localhost:3000/health`

## Database Configuration

The dbhub service connects to a MySQL database:
- Host: `192.168.113.2:3306`
- Database: `asp`
- User: `root`
- Password: `Qr1d8woy`

## Testing

No specific test framework is configured. To add tests:
1. Install a testing framework (Jest, Mocha, etc.)
2. Create test files in a `test/` directory
3. Add test scripts to `package.json`

## Development Notes

- The main entry point is `app/smart-mcp-proxy-sdk.js` which uses modern ESM imports
- Services are spawned as child processes and communicate via JSON-RPC over stdio
- Tool discovery is automatic - tools are registered dynamically when services initialize
- Error handling includes timeouts and proper cleanup of child processes
- The proxy handles both initialization and ongoing tool calls for all services
- **Debug logging is comprehensive** - all HTTP and MCP traffic is logged with timestamps
- File structure changed: main files moved to `app/` directory for Docker containerization

## Debug Logging

The application includes extensive debug logging via the `DebugLogger` class:

- `[HTTP_IN]` - Incoming HTTP requests (method, URL, headers, body)
- `[HTTP_OUT]` - Outgoing HTTP responses (status, headers, body)
- `[MCP_OUT]` - MCP requests sent to services (→ serviceName)
- `[MCP_IN]` - MCP responses from services (← serviceName)
- All logs include ISO timestamps for precise debugging

## Container Structure

The Dockerfile has been updated to copy from `app/` directory:
- Source files are in `app/`
- Dependencies installed in container
- Simplified build process without puppeteer binary download