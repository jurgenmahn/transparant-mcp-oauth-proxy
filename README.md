# MCP Launcher: Universal Model Context Protocol Bridge

**MCP Launcher** is a powerful, containerized bridge that connects multiple Model Context Protocol (MCP) services into a unified interface. It provides a dynamic configuration dashboard, comprehensive MCP service management, and seamless integration with AI assistants like Claude.

Transform your AI workflow by connecting filesystem access, memory management, git operations, web scraping, database queries, and browser automation through a single, elegant interface.

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
- **Real-time Stats:** Monitor MCP service usage with live statistics

### 🛡️ Built-in OAuth2 Provider
- **Full OAuth2/OIDC Support:** Powered by ORY Hydra for enterprise-grade authentication
- **Dynamic Client Registration:** Automatic client registration with configurable redirect domains
- **Flexible Scopes:** Customizable OAuth2 scopes including `openid`, `profile`, `email`, `mcp:read`
- **Session Management:** Secure session handling with Redis backend

### 🐳 Container-First Architecture
- **Docker-based Deployment:** Single container with all dependencies included
- **Service Health Monitoring:** Built-in health checks and status reporting
- **Scalable Design:** Ready for production with proper logging and monitoring

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Domain name with SSL certificate (for production OAuth)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/mcp-launcher.git
cd mcp-launcher
```

2. **Create configuration directory:**
```bash
mkdir -p config/app/config config/etc/hydra
```

3. **Copy example configurations:**
```bash
cp examples/local.yaml.example config/app/config/local.yaml
cp examples/dashboard.yaml.example config/app/config/dashboard.yaml
cp examples/hydra-config.yaml.example config/etc/hydra/config.yaml
```

4. **Update configurations:**
   - Edit `config/app/config/local.yaml` with your domain and settings
   - Edit `config/etc/hydra/config.yaml` with your OAuth settings
   - Generate secure secrets (see Configuration section)

5. **Start the services:**
```bash
docker-compose up -d
```

6. **Access the dashboard:**
   - Open `https://yourdomain.com/dashboard`
   - Login with default credentials (change immediately!)

## 📁 Project Structure

```
mcp-launcher/
├── app/
│   ├── config/
│   │   ├── local.yaml           # Main configuration
│   │   ├── dashboard.yaml       # Dashboard users & settings
│   │   └── statistics.yaml      # Service usage stats
│   ├── src/                     # Application source code
│   └── templates/               # HTML templates
├── config/                      # Mounted configuration
│   ├── app/config/             # App configurations
│   └── etc/hydra/              # Hydra OAuth configurations
├── docker-compose.yml
├── Dockerfile
└── examples/                    # Example configurations
```

## ⚙️ Configuration

### Main Configuration (`local.yaml`)

```yaml
server:
  log_level: info
  skip_mcp_server_loading: false

server_port: 3000

hydra:
  hostname: 127.0.0.1
  public_port: 4444
  admin_port: 4445
  public_url: https://your-domain.com
  admin_url: http://127.0.0.1:4445/admin

oauth:
  session_secret: "GENERATE_RANDOM_SECRET_HERE"
  allowed_redirect_domains:
    - claude.ai
    - anthropic.com
    - your-domain.com
    - localhost
  allowed_scopes:
    - openid
    - profile
    - email
    - mcp:read

cors:
  allowed_origins:
    - https://your-domain.com
    - https://claude.ai
    - http://localhost

redis:
  host: localhost
  port: 6379

# MCP Services Configuration
mcp_services:
  - enabled: true
    name: memory
    startup_command: npx -y @modelcontextprotocol/server-memory
    options: []
    
  - enabled: true
    name: filesystem
    startup_command: npx -y @modelcontextprotocol/server-filesystem
    options:
      - /workspace
      
  - enabled: true
    name: git
    startup_command: npx -y @cyanheads/git-mcp-server
    options: []
    
  - enabled: true
    name: fetch
    startup_command: npx -y @tokenizin/mcp-npx-fetch
    options: []
    
  - enabled: true
    name: playwright
    startup_command: npx @playwright/mcp@latest
    options:
      - --viewport-size=1920,1080
      - --caps=vision,pdf
      - --headless
      - --isolated
      - --no-sandbox

# OAuth Users (for MCP access)
users:
  - email: admin@example.com
    password_hash: "$2b$12$GENERATE_BCRYPT_HASH_HERE"
```

### Dashboard Configuration (`dashboard.yaml`)

```yaml
dashboard:
  users:
    - email: admin@example.com
      password_hash: "$2a$12$GENERATE_BCRYPT_HASH_HERE"
  configs:
    files:
      - type: yaml
        name: MCP Server configuration
        location: /node-apps/config/local.yaml
      - type: yaml
        name: Hydra configuration
        location: /etc/hydra/config.yaml
```

### Hydra OAuth Configuration (`hydra-config.yaml`)

```yaml
dsn: sqlite:///hydra-data/hydra.sqlite?_fk=true

urls:
  self:
    issuer: https://your-domain.com/oauth
  login: https://your-domain.com/oauth/login
  consent: https://your-domain.com/oauth/consent

serve:
  public:
    port: 4444
  admin:
    port: 4445
    cors:
      enabled: true

log:
  level: info
  leak_sensitive_values: false

secrets:
  system:
    - "GENERATE_RANDOM_SECRET_HERE"

oidc:
  dynamic_client_registration:
    enabled: true
    default_scope:
      - openid
      - profile
      - email
      - mcp:read

webfinger:
  oidc_discovery:
    client_registration_url: https://your-domain.com/oauth/register
```

### Docker Compose Example

```yaml
version: '3.8'

services:
  mcp-launcher:
    build: 
      context: .
    container_name: mcp-launcher
    restart: unless-stopped  
    ports:
      - "3000:3000"
      - "4444:4444"
      - "4445:4445"
    volumes:
      - ./mcp-workspace:/workspace
      - ./hydra-db:/hydra-data
      - ./redis-data:/var/lib/redis
      - ./config/app/config:/node-apps/config
      - ./config/etc/hydra:/etc/hydra
    environment:
      - NODE_ENV=production
```

### Generating Secure Secrets

Use the dashboard's built-in secret generator or generate manually:

```bash
# Generate random secret (32 bytes, base64)
openssl rand -base64 32

# Generate bcrypt hash for passwords
npx bcrypt-cli hash-password "your-password-here" 12
```

## 🛠️ Usage Examples

### Connecting to Claude

1. **Configure OAuth in Claude:**
   - Use your domain's OAuth endpoint: `https://your-domain.com/oauth2/auth`
   - Set MCP endpoint: `https://your-domain.com/`
   - Include required scopes: `openid profile email mcp:read`

2. **Available Tools:**
   All configured MCP services expose their tools in one unified toolbox:
   - `memory_store` - Store information in knowledge graph
   - `filesystem_read` - Read files from configured directories  
   - `git_status` - Check repository status
   - `fetch_get` - Retrieve web content
   - `playwright_screenshot` - Capture webpage screenshots
   - Custom tools from any added MCP services

### Adding Custom MCP Services

Through the dashboard or by editing `local.yaml`:

```yaml
mcp_services:
  - enabled: true
    name: custom-service
    startup_command: npx your-custom-mcp-server
    options:
      - --config=/path/to/config
    install: "npm install -g your-custom-mcp-server"
```

## 🔧 Custom Install Scripts

The MCP Launcher supports custom installation scripts that run during Docker build time to extend the container with additional software or configurations. This mechanism allows you to install custom packages, tools, or dependencies that your MCP services might require.

### How Custom Install Scripts Work

1. **Script Location**: Place your custom shell scripts (`.sh` files) in the `custom-install-scripts/` directory
2. **Build Integration**: During Docker build, the `install-custom-scripts.sh` script automatically discovers and executes all `.sh` files in alphabetical order
3. **Change Tracking**: The system tracks all filesystem changes made by each script and packages them into compressed archives
4. **Efficient Caching**: Each script's changes are cached separately, so rebuilding only affects modified scripts

### Script Execution Process

The installation process (`conf/scripts/install-custom-scripts.sh`) performs these steps for each script:

1. **Discovery**: Finds all `.sh` files in `/custom-install-scripts`
2. **Timestamp Check**: Creates a unique package name based on script modification time
3. **Cache Check**: Skips execution if a package for the current script version already exists
4. **Pre-execution Snapshot**: Creates a timestamp marker before running the script
5. **Script Execution**: Runs the script with full logging
6. **Change Capture**: Identifies all files modified/created after the timestamp marker
7. **Package Creation**: Compresses changes into a `.tar.gz` package in `/install-packages`

### Docker Integration

In the Dockerfile:

```dockerfile
# Copy custom scripts and installer
COPY ./custom-install-scripts /custom-install-scripts
COPY ./conf/scripts/install-custom-scripts.sh /

# Execute custom installations with caching
RUN --mount=type=cache,target=/var/cache/apt \
    mkdir -p /install-packages/ && \
    chmod +x /install-custom-scripts.sh && \
    /install-custom-scripts.sh

# Later in the build process, extract all packages
COPY --from=custom-script-installer /install-packages /install-packages
RUN cd /install-packages && for pkg in *.tar.gz; do \
    [ -f "$pkg" ] && echo "Installing $pkg" && tar -xzf "$pkg" -C / \
    && echo "Success: $pkg" || echo "Failed: $pkg"; done
```

### Example Custom Install Script

Create `custom-install-scripts/install-python-tools.sh`:

```bash
#!/bin/bash
echo "Installing Python development tools"
apt-get update
apt-get install -y python3-dev python3-pip
pip3 install requests beautifulsoup4 pandas
echo "Python tools installation complete"
```

### Benefits

- **Modular**: Each script is independent and cached separately
- **Efficient**: Only changed scripts are re-executed on rebuilds  
- **Trackable**: Full logging of installation process and changes
- **Flexible**: Support any shell commands or installation procedures
- **Docker-Optimized**: Integrates with Docker's layer caching for optimal build performance

### Logging and Debugging

All script executions are logged with timestamps to `/tmp/install-scripts-YYYYMMDD-HHMMSS.log`, including:
- Script discovery and processing order
- Execution success/failure status
- Duration of each script execution  
- Package creation results
- Summary statistics (successful/skipped/failed counts)

## 📊 Monitoring & Administration

### Health Endpoints

```bash
# Overall system health
curl https://your-domain.com/health

# Individual service status
curl https://your-domain.com/services

# MCP statistics
curl https://your-domain.com/dashboard/api/mcp-stats
```

### Dashboard Features

- **General Tab:** Server settings, ports, log levels
- **MCP Tab:** Service management, user configuration
- **Hydra Tab:** OAuth provider settings
- **Stats Tab:** Real-time service usage statistics
- **Users Tab:** Dashboard user management
- **Admin Tab:** Redis management, Hydra client administration

### Debug Console

Access detailed request/response logging at `https://your-domain.com/debug`

## 🔒 Security Features

- **Bcrypt Password Hashing:** All passwords stored with bcrypt (cost 12)
- **CORS Protection:** Configurable allowed origins
- **OAuth2/OIDC Compliance:** Enterprise-grade authentication
- **Session Management:** Secure Redis-backed sessions
- **Domain Validation:** Restricted redirect domains
- **Input Validation:** YAML validation with rollback on errors

## 🐛 Troubleshooting

### Common Issues

1. **Services not starting:**
   - Check `docker-compose logs mcp-launcher`
   - Verify MCP service installation commands
   - Ensure workspace directories exist

2. **OAuth authentication fails:**
   - Verify domain configuration in all config files
   - Check SSL certificate validity
   - Confirm Hydra service is running

3. **Dashboard access denied:**
   - Verify dashboard user credentials
   - Check bcrypt hash generation
   - Ensure session secret is configured

### Log Analysis

```bash
# Application logs
docker-compose logs -f mcp-launcher

# Real-time debug output
curl https://your-domain.com/debug
```

## 🤝 Contributing

We welcome contributions! Areas where help is needed:

- 🐛 **Bug Reports:** Found something broken? Open an issue
- 💡 **Feature Requests:** Have ideas? Let's discuss them
- 🔧 **Code Contributions:** PRs welcome for improvements
- 📖 **Documentation:** Help improve setup guides
- 🧪 **Testing:** Help test with different MCP services

### Development Setup

1. Clone and setup development environment
2. Copy example configurations
3. Use `npm run dev` for hot reloading
4. Test with various MCP services

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🙏 Acknowledgments

**Built with human ingenuity & AI collaboration**

This project represents the intersection of practical DevOps needs and cutting-edge AI tooling. Every feature solves real-world integration challenges.

**Authored by:** The MCP Community with AI assistance

*"Bridging the gap between AI capabilities and practical implementation."*

---

**⚡ Ready to supercharge your AI workflow? ⚡**

*Found this project useful? Give it a ⭐ and help others discover it!*