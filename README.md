# MCP Launcher: Universal Model Context Protocol Bridge

**MCP Launcher** is a powerful, containerized bridge that connects multiple Model Context Protocol (MCP) services into a unified interface. It provides a dynamic configuration dashboard, comprehensive MCP service management, and seamless integration with AI assistants like Claude.

Transform your AI workflow by connecting filesystem access, memory management, git operations, web scraping, database queries, and browser automation through a single, elegant interface.

---

## ✨ Key Features

### 🔗 MCP Service Bridge
- **Universal MCP Proxy:** Connects multiple MCP services (memory, filesystem, git, fetch, playwright, database) through a single endpoint
- **Add Any Node.js MCP Service:** Easily add any Node.js-based MCP service through the dashboard configuration
- **Unified Toolbox:** All configured MCP services are exposed as one consolidated toolbox to MCP clients
- **Dynamic Tool Discovery:** Automatically registers and exposes 79+ tools from connected services
- **Real-time Service Management:** Monitor, restart, and manage individual MCP services
- **Intelligent Routing:** Routes tool calls to appropriate services with proper error handling

### 🎛️ Configuration Dashboard  
- **Web-based Configuration:** Manage all settings through an intuitive dashboard at `/dashboard`
- **Live Field Population:** Configuration fields are automatically populated from existing config files
- **Smart Password Management:** Secure password fields with edit/show functionality
- **User Management:** Add, edit, and delete dashboard users with role-based access
- **30% Wider Interface:** Optimized layout for better usability

### 🛡️ Built-in OAuth2 Provider
- **Full OAuth2/OIDC Support:** Powered by ORY Hydra for enterprise-grade authentication
- **Dynamic Client Registration:** Automatic client registration with configurable redirect domains
- **Flexible Scopes:** Customizable OAuth2 scopes including `openid`, `profile`, `email`, `mcp:read`
- **Session Management:** Secure session handling with Redis backend

### 🐳 Container-First Architecture
- **Docker-based Deployment:** Single container with all dependencies included
- **Service Health Monitoring:** Built-in health checks and status reporting
- **Scalable Design:** Ready for production with proper logging and monitoring

---

## 🔧 MCP Services Integration

The launcher connects to multiple MCP services, each providing specialized tools. **Any Node.js-based MCP service can be added** through the dashboard configuration - simply provide the npm package name, startup command, and optional configuration parameters.

| Service | Tools | Description |
|---------|-------|-------------|
| **Memory** | 9 tools | Knowledge graph, entity storage, relationship mapping |
| **Filesystem** | 12 tools | File operations, directory management, secure access |
| **Git** | 25 tools | Repository management, commit operations, branch handling |
| **Fetch** | 4 tools | Web scraping, HTTP requests, content retrieval |
| **Playwright** | 28 tools | Browser automation, screenshot capture, web testing |
| **Database** | 1 tool | MySQL database queries and operations |

### Example MCP Usage URLs

For use with Claude.ai or other MCP clients:

```
# Main MCP endpoint (SSE)
https://your-domain.com/sse

# Health monitoring
https://your-domain.com/health

# Service status
https://your-domain.com/services
```

---

## 📋 Requirements

- **Docker & Docker Compose:** For container deployment
- **Redis:** For session storage (included in docker-compose)
- **Reverse Proxy (Recommended):** Nginx or Traefik for HTTPS termination
- **MySQL Database (Optional):** For database MCP service functionality

---

## 🚀 Installation & Setup

### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd mcp-launcher

# Build and start the services
docker-compose up --build -d

# Check service status
docker-compose logs -f app
```

### First-Time Setup

1. **Access the Dashboard:**
   - URL: `http://localhost:3000/dashboard`  
   - Default credentials: `admin@email.com` / `mcp-admin`

2. **Configure Services:**
   - Review MCP service configurations
   - Set up OAuth2 domain settings
   - Configure user access permissions

3. **Test MCP Connection:**
   ```bash
   # Test health endpoint
   curl http://localhost:3000/health
   
   # Test MCP SSE endpoint
   curl -H "Accept: text/event-stream" http://localhost:3000/sse
   ```

---

## ⚙️ Configuration Files

### Primary Configuration: `app/config/local.yaml`

Contains all main application settings:

```yaml
# Server configuration  
server:
  log_level: debug
  public_url: https://your-domain.com
  session_secret: <44-char-hash>
  server_port: 3000

# OAuth2 settings
oauth:
  allowed_redirect_domains:
    - your-domain.com
  allowed_origins:
    - https://your-trusted-domain.com

# MCP Services configuration - Add any Node.js MCP service!
mcp_services:
  - name: memory
    startup_command: npx @modelcontextprotocol/server-memory
    options: []
    install: "npm install -g @modelcontextprotocol/server-memory"
    
  - name: filesystem  
    startup_command: npx @modelcontextprotocol/server-filesystem
    options: ["/workspace"]
    
  - name: your-custom-service
    startup_command: npx your-awesome-mcp-package
    options: ["--custom-flag", "value"]
    install: "npm install -g your-awesome-mcp-package"
    
  # ... any Node.js MCP service can be added here!

# Dashboard users
users:
  - email: admin@email.com
    password_hash: <bcrypt-hash>
```

### Hydra OAuth2 Configuration: `conf/etc/hydra/config.yaml`

OAuth2 provider settings including:
- Database connection (SQLite)
- Public/admin ports (4444/4445)
- URL endpoints for issuer, login, consent
- Security secrets and OIDC settings

### Dashboard Users: Managed through web interface

Users are stored in `local.yaml` and managed through the dashboard with:
- Email-based authentication
- Bcrypt password hashing
- Session-based access control
- Self-service password changes

---

## 🔌 MCP Proxy Architecture

### How It Works

1. **Service Discovery:** Launcher spawns child processes for each configured MCP service
2. **Tool Registration:** Each service's tools are discovered via `tools/list` JSON-RPC calls  
3. **Unified Toolbox Creation:** All tools from all services are consolidated into a single toolbox for MCP clients
4. **Dynamic Routing:** Tools are prefixed with service names (`memory_read`, `git_status`, etc.) and routed intelligently
5. **Request Handling:** Client requests are parsed and routed to appropriate services
6. **Response Streaming:** Results are streamed back via Server-Sent Events (SSE)

**The key advantage:** MCP clients see all your configured services as one unified toolbox, making it seamless to use tools from different services in a single conversation or workflow.

### Protocol Support

- **JSON-RPC 2.0:** Standard MCP protocol communication
- **Server-Sent Events:** Real-time streaming for client connections
- **HTTP REST:** Health monitoring and service management endpoints
- **WebSocket:** Future support planned for enhanced real-time communication

---

## 🛠️ Usage Examples

### With Claude.ai

1. Configure Claude to use your MCP endpoint:
   ```
   MCP Server URL: https://your-domain.com/sse
   ```

2. Available tools will include all tools from all configured services in one unified toolbox:
   - `memory_store` - Store information in knowledge graph
   - `filesystem_read` - Read files from configured directories  
   - `git_status` - Check repository status
   - `fetch_get` - Retrieve web content
   - `playwright_screenshot` - Capture webpage screenshots
   - `dbhub_query` - Execute database queries
   - `your_custom_service_tool` - Any tools from custom MCP services you've added

**Pro tip:** Claude will see all these tools as one cohesive toolbox, allowing seamless workflows like "read a file, process it with a custom tool, store results in memory, and commit changes to git" - all in one conversation!

### Direct API Usage

```bash
# Get available tools
curl -X POST https://your-domain.com/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Call a specific tool
curl -X POST https://your-domain.com/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/call",
    "params":{
      "name":"memory_store",
      "arguments":{"content":"Important information to remember"}
    }
  }'
```

---

## 📊 Monitoring & Debugging

### Health Monitoring

```bash
# Overall system health
curl http://localhost:3000/health

# Individual service status
curl http://localhost:3000/services

# Restart specific service
curl -X POST http://localhost:3000/restart/memory
```

### Log Analysis

The application provides comprehensive logging:

- **HTTP Traffic:** All incoming requests and responses
- **MCP Communication:** JSON-RPC messages between services  
- **Service Management:** Startup, shutdown, and error events
- **Performance Metrics:** Response times and tool usage statistics

Access logs via:
```bash
# Application logs
docker-compose logs -f app

# Service-specific logs  
docker-compose exec app tail -f /tmp/server.log
```

---

## 🔐 Security Considerations

- **OAuth2 Security:** Full PKCE support, secure token handling
- **Filesystem Isolation:** Configurable allowed directories for filesystem service
- **Session Security:** Redis-backed sessions with configurable timeouts
- **Input Validation:** Comprehensive parameter validation for all tools
- **CORS Protection:** Configurable allowed origins and methods

---

## 🤝 Contributing

We welcome contributions! Whether it's:

- 🐛 **Bug Reports:** Found something broken? Let us know!
- 💡 **Feature Requests:** Have an idea? We'd love to hear it
- 🔧 **Code Contributions:** PRs are always welcome
- 📖 **Documentation:** Help make the docs even better

Check out our [Issues](https://github.com/jurgenmahn/transparant-mcp-oauth-proxy/issues) for current priorities and discussions.

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

**Built with human ingenuity & AI collaboration**

This project emerged from late-night coding sessions, unexpected inspiration, and the occasional debugging dance. Every line of code has a story behind it.

**Authored by:** Jurgen Mahn with assistance from AI coding companions Claude and Codex

*"Sometimes the code writes itself. Other times, we collaborate with the machines."*

**⚡ Happy hacking, fellow explorer ⚡**

---

*Found this project useful? Give it a ⭐ and help others discover it!*