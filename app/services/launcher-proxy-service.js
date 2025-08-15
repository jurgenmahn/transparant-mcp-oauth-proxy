// mcp-bridge-server.js - Dynamic MCP bridge with auto tool discovery
import {
    McpServer
} from "@modelcontextprotocol/sdk/server/mcp.js";
import {
    StdioServerTransport
} from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    StreamableHTTPServerTransport
} from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
    z
} from "zod";
import {
    spawn
} from "child_process";
import express from "express";
import fs from "fs";
import path from "path";
import YAML from "yaml";
// Debug logging utility
class DebugLogger {
    static log(category, message, data = null) {
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] [${category}] ${message}`);
        if (data) {
            console.log(`[${timestamp}] [${category}] Data:`, JSON.stringify(data, null, 2));
        }
    }

    static logHttpRequest(req) {
        this.log('HTTP_IN', `${req.method} ${req.url}`, {
            headers: req.headers,
            body: req.body,
            query: req.query,
            params: req.params
        });
    }

    static logHttpResponse(res, body) {
        this.log('HTTP_OUT', `Response ${res.statusCode}`, {
            headers: res.getHeaders(),
            body: body
        });
    }

    static logMCPRequest(serviceName, request) {
        this.log(`MCP_OUT:${serviceName}`, `→ ${serviceName}`, request);
    }

    static logMCPResponse(serviceName, response) {
        this.log(`MCP_IN:${serviceName}`, `← ${serviceName}`, response);
    }
}

export class LauncherProxyService {
    constructor(appPath) {
        this.appPath = appPath;
        this.router = express.Router();
        this.config = {};
        this.processes = new Map();
        this.pendingRequests = new Map();
        this.requestIdCounter = 1;
        this.registeredTools = new Set(); // Track registered tools to prevent duplicates
        this.activeServers = new Set(); // Track active server instances for notifications
        this.lastToolListHash = null;
        this.lastResourceListHash = null;
        this.lastPromptListHash = null;

        // Performance optimizations - cache expensive operations
        this.cachedHealthStatus = null;
        this.lastHealthStatusUpdate = 0;
        this.healthStatusCacheTTL = 5000; // 5 seconds cache

        this.cachedServicesList = null;
        this.lastServicesListUpdate = 0;
        this.servicesListCacheTTL = 2000; // 2 seconds cache

        this.setupRoutes();
        this.failedServices = new Set(); // Services that failed and should not auto-retry
    }

    writeMessage(serviceName, obj) {
        const service = this.processes.get(serviceName);
        if (service?.ioProtocol === 'framed') return this.writeFramed(serviceName, obj);
        return this.writeJsonl(serviceName, obj);
    }

    writeFramed(serviceName, obj) {
        const service = this.processes.get(serviceName);
        if (!service || !service.proc || !service.proc.stdin) return;
        const payload = JSON.stringify(obj);
        const headers = `Content-Length: ${Buffer.byteLength(payload, 'utf8')}`;
        const framed = `${headers}\r\n\r\n${payload}`;
        try {
            service.proc.stdin.write(framed);
        } catch (e) {
            console.error(`[${serviceName}] Failed to write framed message:`, e?.message || e);
        }
    }

    writeJsonl(serviceName, obj) {
        const service = this.processes.get(serviceName);
        if (!service || !service.proc || !service.proc.stdin) return;
        const payload = JSON.stringify(obj) + '\n';
        try {
            service.proc.stdin.write(payload);
        } catch (e) {
            console.error(`[${serviceName}] Failed to write JSONL message:`, e?.message || e);
        }
    }

    async initialize() {
        await this.loadConfig();
        this.loadStats();
        await this.initializeMCPServer();
        console.log('Launcher Proxy Service initialized');
    }

    // Reload configuration and restart all MCP child processes without recreating the persistent MCP server
    async reloadFromConfig() {
        console.log('[LauncherProxy] 🔁 Reloading configuration and restarting MCP services...');
        // Kill existing processes
        try {
            for (const [name, svc] of this.processes) {
                try { svc.proc && svc.proc.kill(); } catch {}
            }
            await new Promise(r => setTimeout(r, 1000));
        } catch {}

        // Reset state that depends on running services
        this.processes = new Map();
        this.pendingRequests = new Map();
        this.registeredTools = new Set();
        this.invalidateHealthCache();
        this.invalidateServicesCache();

        // Reload config and parsed services
        await this.loadConfig();
        this.services = await this.parseServices(this.config.mcp_services || []);

        // Start all services again
        await this.startAllServices();

        // Notify connected clients about tool/resource/prompt changes
        this.notifyToolListChanged();
        this.notifyResourceListChanged();
        this.notifyPromptListChanged();
        console.log('[LauncherProxy] ✅ Reload completed');
    }

    // --- Statistics tracking ---
    get statsFilePath() {
        try {
            return path.resolve(this.appPath + '/config/statistics.yaml');
        } catch {
            return this.appPath + '/config/statistics.yaml';
        }
    }

    loadStats() {
        try {
            if (fs.existsSync(this.statsFilePath)) {
                const txt = fs.readFileSync(this.statsFilePath, 'utf-8');
                this.stats = YAML.parse(txt) || { services: {} };
            } else {
                this.stats = { services: {} };
            }
        } catch (e) {
            console.warn('Failed to load statistics.yaml, starting fresh:', e.message);
            this.stats = { services: {} };
        }
    }

    saveStats() {
        try {
            const out = YAML.stringify(this.stats || { services: {} });
            fs.writeFileSync(this.statsFilePath, out, 'utf-8');
        } catch (e) {
            console.warn('Failed to save statistics.yaml:', e.message);
        }
    }

    async loadConfig() {
        try {
            this.config = YAML.parse(fs.readFileSync(this.appPath + '/config/local.yaml', 'utf-8'));
        } catch (error) {
            console.error('Error loading launcher proxy config:', error);
            throw error;
        }
    }

    async initializeMCPServer() {
        // Parse services configuration
        this.services = await this.parseServices(this.config.mcp_services || []);

        const mcpServerNames = Object.keys(this.services).join(", ");
        console.log("MCP servers loaded from configuration: ", mcpServerNames);

        // Optional skip flag for faster debug cycles
        const skip = !!(this.config?.server?.skip_mcp_server_loading === true || this.config?.server?.skip_mcp_server_loading === 'true');
        this.skipMcpLoading = skip;

        if (skip) {
            console.log("⏭️  Skipping MCP service startup per config (server.skip_mcp_server_loading=true). Faking start for debugging.");
        } else {
            console.log("🔧 Starting MCP Bridge services...");
            // Start all backend services and register their tools
            await this.startAllServices();
        }

        // Initialize the persistent MCP server and transport
        this.mcpServer = this.createServer();
        this.transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined, // Disable session management for stateless mode
            enableJsonResponse: false // Use SSE streaming
        });

        await this.mcpServer.connect(this.transport);
        console.log("✅ Persistent MCP server and transport initialized");
    }

    // Register all tools from all services to a server instance (cached, no verbose logging)
    registerAllToolsCached(server) {
        let toolCount = 0;

        for (const [serviceName, service] of this.processes) {
            if (service.tools && service.initialized) {
                for (const tool of service.tools) {
                    const toolName = `${serviceName}_${tool.name}`;

                    // Convert the tool's inputSchema to zod schema
                    const zodSchema = this.convertToZodSchema(tool.inputSchema);

                    // Register the tool
                    server.tool(
                        toolName,
                        `[${serviceName.toUpperCase()}] ${tool.description}`,
                        zodSchema,
                        async (parameters) => {
                            try {
                                const result = await this.callTool(serviceName, tool.name, parameters);

                                // Format the result nicely
                                let resultText;
                                if (typeof result === 'string') {
                                    resultText = result;
                                } else if (result && typeof result === 'object') {
                                    resultText = JSON.stringify(result, null, 2);
                                } else {
                                    resultText = String(result || 'Operation completed successfully');
                                }

                                return {
                                    content: [{
                                        type: "text",
                                        text: `✅ ${tool.name} result:\n\n${resultText}`
                                    }]
                                };
                            } catch (error) {
                                return {
                                    content: [{
                                        type: "text",
                                        text: `❌ Error calling ${tool.name}: ${error.message}`
                                    }]
                                };
                            }
                        }
                    );
                    toolCount++;
                }
            }
        }

        // Only log once when creating a new server instance
        if (toolCount > 0) {
            console.log(`✅ Registered ${toolCount} tools for new server instance`);
        }
    }

    // Parse service configurations - support both old and new formats
    async parseServices(mcpServicesConfig) {
        const services = {};

        if (Array.isArray(mcpServicesConfig)) {
            // New format: array of service objects
            for (const serviceConfig of mcpServicesConfig) {
                if (serviceConfig && serviceConfig.name && serviceConfig.startup_command) {
                    // Skip disabled services (accept boolean false or string 'false')
                    const enabled = !(serviceConfig.enabled === false || serviceConfig.enabled === 'false');
                    if (!enabled) {
                        console.log(`⏭️  Skipping disabled MCP service: ${serviceConfig.name}`);
                        continue;
                    }
                    // Parse startup_command string into array
                    const commandParts = serviceConfig.startup_command.split(/\s+/);

                    // Add options if present
                    let fullCommand = commandParts;
                    if (serviceConfig.options && Array.isArray(serviceConfig.options)) {
                        fullCommand = [...commandParts, ...serviceConfig.options];
                    }

                    // Normalize env vars if present (accept array of {key,value} or object map)
                    let envMap = undefined;
                    if (serviceConfig.env) {
                        if (Array.isArray(serviceConfig.env)) {
                            envMap = {};
                            for (const pair of serviceConfig.env) {
                                if (!pair) continue;
                                const k = (pair.key || pair.name || '').toString();
                                if (!k) continue;
                                envMap[k] = pair.value != null ? String(pair.value) : '';
                            }
                        } else if (typeof serviceConfig.env === 'object') {
                            envMap = {};
                            for (const [k, v] of Object.entries(serviceConfig.env)) {
                                if (!k) continue;
                                envMap[k] = v != null ? String(v) : '';
                            }
                        }
                    }

                    // Store install commands if present - handle different formats
                    let installCommands = null;
                    if (serviceConfig.install) {
                        if (Array.isArray(serviceConfig.install)) {
                            // Check if it's an array of characters (YAML parsing issue)
                            if (serviceConfig.install.length > 0 && typeof serviceConfig.install[0] === 'string' && serviceConfig.install[0].length === 1) {
                                // Join character array back into string
                                installCommands = serviceConfig.install.join('');
                            } else {
                                // Normal array of commands
                                installCommands = [...serviceConfig.install];
                            }
                        } else if (typeof serviceConfig.install === 'string') {
                            installCommands = serviceConfig.install;
                        } else {
                            installCommands = serviceConfig.install;
                        }
                    }

                    // Protocol override from config or heuristic (python servers often use framed LSP)
                    let protocol = undefined;
                    try {
                        const cfgProto = (serviceConfig.protocol || '').toString().toLowerCase();
                        if (cfgProto === 'jsonl' || cfgProto === 'framed') {
                            protocol = cfgProto;
                        } else if (cfgProto === 'auto') {
                            protocol = undefined;
                        } else {
                            const sc = String(serviceConfig.startup_command || '').toLowerCase();
                            if (/(^|\s)(python|pypy)\b/.test(sc) || /\.py(\s|$)/.test(sc) || /(^|\s)uvx(\s|$)/.test(sc)) {
                                protocol = 'framed';
                            }
                        }
                    } catch {}

                    services[serviceConfig.name] = {
                        command: fullCommand,
                        install: installCommands,
                        env: envMap,
                        protocol
                    };
                }
            }
        } else if (typeof mcpServicesConfig === 'object' && mcpServicesConfig !== null) {
            // Old format: object with service names as keys and arrays as values
            for (const [serviceName, command] of Object.entries(mcpServicesConfig)) {
                if (Array.isArray(command)) {
                    services[serviceName] = {
                        command: command,
                        install: null
                    };
                }
            }
        }

        return services;
    }

    async startService(serviceName, serviceConfig) {
        console.log(`🔧 Starting ${serviceName} service...`);
        if (this.failedServices.has(serviceName)) {
            console.log(`⏭️  Skipping start for ${serviceName} (marked failed). Use manual restart to retry.`);
            return null;
        }

        // Handle install commands if present
        if (serviceConfig.install) {
            console.log(`📦 Installing packages for ${serviceName}...`);
            console.log(`📋 Install config type: ${typeof serviceConfig.install}`);
            console.log(`📋 Install config value:`, JSON.stringify(serviceConfig.install, null, 2));

            try {
                // Handle both array format and multiline string format
                let installCommands = [];

                if (Array.isArray(serviceConfig.install)) {
                    console.log(`📋 Processing as array with ${serviceConfig.install.length} commands`);
                    installCommands = serviceConfig.install;
                } else if (typeof serviceConfig.install === 'string') {
                    console.log(`📋 Processing as string, length: ${serviceConfig.install.length}`);
                    console.log(`📋 Contains newlines: ${serviceConfig.install.includes('\n')}`);
                    console.log(`📋 Contains sh -c: ${serviceConfig.install.includes('sh -c')}`);
                    // For multiline string, execute as a shell script
                    installCommands = [serviceConfig.install];
                }

                console.log(`📋 Total install commands to execute: ${installCommands.length}`);

                for (let i = 0; i < installCommands.length; i++) {
                    const installCmd = installCommands[i];
                    console.log(`🔄 [${i + 1}/${installCommands.length}] Starting install command...`);
                    console.log(`📝 Command preview: ${installCmd.substring(0, 100)}${installCmd.length > 100 ? '...' : ''}`);

                    const startTime = Date.now();
                    let installProc;

                    if (typeof installCmd === 'string' && (installCmd.includes('\n') || installCmd.includes('sh -c'))) {
                        console.log(`🐚 Executing as shell script with 'sh -c'`);
                        installProc = spawn('sh', ['-c', installCmd], {
                            stdio: ['pipe', 'pipe', 'pipe']
                        });
                    } else {
                        console.log(`⚡ Executing as parsed command`);
                        const installParts = installCmd.split(/\s+/);
                        console.log(`📝 Parsed parts:`, installParts);
                        installProc = spawn(installParts[0], installParts.slice(1), {
                            stdio: ['pipe', 'pipe', 'pipe']
                        });
                    }

                    console.log(`🚀 Process spawned with PID: ${installProc.pid}`);

                    await new Promise((resolve, reject) => {
                        let stdout = '';
                        let stderr = '';
                        let outputLines = 0;

                        

                        installProc.stdout.on('data', (data) => {
                            stdout += data.toString();
                            const lines = data.toString().split('\n').filter(line => line.trim());
                            outputLines += lines.length;
                            console.log(`📤 [STDOUT] ${lines.join('\n📤 [STDOUT] ')}`);
                        });

                        installProc.stderr.on('data', (data) => {
                            stderr += data.toString();
                            const lines = data.toString().split('\n').filter(line => line.trim());
                            console.log(`📥 [STDERR] ${lines.join('\n📥 [STDERR] ')}`);
                        });

                        installProc.on('close', (code) => {
                            const duration = Date.now() - startTime;
                            console.log(`🏁 Process finished in ${duration}ms with exit code: ${code}`);
                            console.log(`📊 Output lines captured: ${outputLines}`);

                            if (code === 0) {
                                console.log(`  ✅ Install command [${i + 1}/${installCommands.length}] completed successfully`);
                                resolve();
                            } else {
                                console.error(`  ❌ Install command [${i + 1}/${installCommands.length}] failed with exit code ${code}`);
                                console.error(`📋 Final stderr:`, stderr);
                                reject(new Error(`Install failed with code ${code}: ${stderr}`));
                            }
                        });

                        installProc.on('error', (error) => {
                            const duration = Date.now() - startTime;
                            console.error(`💥 Process error after ${duration}ms:`, error);
                            reject(error);
                        });

                        // Add timeout protection
                        setTimeout(() => {
                            if (!installProc.killed) {
                                console.log(`⏰ Install command taking longer than 5 minutes, still running...`);
                                try {
                                    const commandString = Array.isArray(installProc.spawnargs) ? installProc.spawnargs.join(' ') : '';
                                    if (commandString) console.log(`install command: ${commandString}`);
                                } catch {}
                            }
                        }, 5 * 60 * 1000); // 5 minutes
                    });
                }
            } catch (error) {
                console.error(`❌ Failed to run install commands for ${serviceName}:`, error.message);
                console.error(`📋 Error stack:`, error.stack);
                // Continue with service startup even if install fails
            }

            console.log(`✅ Package installation completed for ${serviceName}`);
        }

        // Get the actual command to run
        const command = serviceConfig.command || serviceConfig;

        const spawnEnv = { ...process.env };
        // Ensure Python-based servers flush and use UTF-8
        spawnEnv.PYTHONUNBUFFERED = spawnEnv.PYTHONUNBUFFERED || '1';
        spawnEnv.PYTHONIOENCODING = spawnEnv.PYTHONIOENCODING || 'utf-8';
        if (serviceConfig && serviceConfig.env && typeof serviceConfig.env === 'object') {
            Object.assign(spawnEnv, serviceConfig.env);
        }
        const proc = spawn(command[0], command.slice(1), {
            stdio: ['pipe', 'pipe', 'pipe'],
            env: spawnEnv
        });

        const service = {
            proc,
            responseBuffer: '',
            initialized: false,
            tools: [],
            serviceName,
            startTime: Date.now(),
            ioProtocol: serviceConfig.protocol || undefined
        };

        try {
            console.log(`[MCP:${serviceName}] I/O protocol: ${service.ioProtocol || 'jsonl (auto)'}`);
        } catch {}

        this.processes.set(serviceName, service);

        // Handle spawn errors (e.g., ENOENT)
        proc.on('error', (err) => {
            console.error(`[MCP:${serviceName}] ❌ Spawn error: ${err?.message || err}`);
            this.failedServices?.add?.(serviceName);
            this.processes.delete(serviceName);
            this.invalidateHealthCache();
            this.invalidateServicesCache();
            this.notifyToolListChanged();
            this.notifyResourceListChanged();
            this.notifyPromptListChanged();
            this.sendLogToClients('error', `Spawn error for ${serviceName}: ${err?.message || err}`);
        });

        // Handle stdout
        proc.stdout.on('data', (data) => {
            try { service.ready = true; } catch {}
            service.responseBuffer += data.toString();
            this.processServiceOutput(serviceName);
        });

        // Handle stderr
        proc.stderr.on('data', (data) => {
            const output = data.toString().trim();
            if (output && !output.includes('npm WARN') && !output.includes('downloading')) {
                console.log(`[${serviceName}] ${output}`);
            }
        });

        // Handle exit
        proc.on('close', (code, signal) => {
            console.error(`[${serviceName}] ❌ Process exited with code ${code}${signal ? `, signal ${signal}` : ''}`);
            if (code !== 0) {
                this.failedServices.add(serviceName);
            }
            this.processes.delete(serviceName);
            // Invalidate caches immediately
            this.invalidateHealthCache();
            this.invalidateServicesCache();
            // Notify about changes when services go down
            this.notifyToolListChanged();
            this.notifyResourceListChanged();
            this.notifyPromptListChanged();
            this.sendLogToClients('error', `Service ${serviceName} exited with code ${code}`);
        });

        // Initialize the service
        try {
            await this.initializeService(serviceName);
        } catch (e) {
            this.failedServices.add(serviceName);
            throw e;
        }

        return service;
    }

    async initializeService(serviceName) {
        const service = this.processes.get(serviceName);
        if (!service) return;

        try {
            // For framed protocol servers (Python/uvx), wait a brief moment for stdout readiness
            if (service.ioProtocol === 'framed') {
                await new Promise(res => setTimeout(res, 200));
            }
            // Send initialize
            const initRequest = {
                jsonrpc: "2.0",
                id: this.requestIdCounter++,
                method: "initialize",
                params: {
                    protocolVersion: "2025-03-26",
                    capabilities: {},
                    clientInfo: {
                        name: "dynamic-mcp-bridge",
                        version: "1.0.0"
                    }
                }
            };

            DebugLogger.logMCPRequest(serviceName, initRequest);
            this.writeMessage(serviceName, initRequest);
            await this.waitForResponse(initRequest.id, service.ioProtocol === 'framed' ? 30000 : 15000);

            // Send tools/list
            const toolsRequest = {
                jsonrpc: "2.0",
                id: this.requestIdCounter++,
                method: "tools/list",
                params: {}
            };

            DebugLogger.logMCPRequest(serviceName, toolsRequest);
            this.writeMessage(serviceName, toolsRequest);
            const toolsResponse = await this.waitForResponse(toolsRequest.id);

            if (toolsResponse && toolsResponse.result && toolsResponse.result.tools) {
                service.tools = toolsResponse.result.tools;
                service.initialized = true;
                console.log(`✅ ${serviceName} initialized with ${service.tools.length} tools`);

                // Dynamically register all tools from this service
                this.registerServiceTools(serviceName, service.tools);

                // Invalidate caches when services are initialized
                this.invalidateHealthCache();
                this.invalidateServicesCache();

                // Notify about resource and prompt changes too
                this.notifyResourceListChanged();
                this.notifyPromptListChanged();
                this.sendLogToClients('info', `Service ${serviceName} initialized with ${service.tools.length} tools`);
            } else {
                console.log(`⚠️  ${serviceName} initialized but no tools found`);
                service.initialized = true;
                this.invalidateHealthCache();
                this.invalidateServicesCache();
                this.notifyResourceListChanged();
                this.notifyPromptListChanged();
                this.sendLogToClients('info', `Service ${serviceName} initialized but no tools found`);
            }
        } catch (error) {
            console.error(`❌ Failed to initialize ${serviceName}:`, error.message);
        }
    }

    registerServiceTools(serviceName, tools) {
        console.log(`🔧 registerServiceTools called for ${serviceName} with ${tools.length} tools. Current registered count: ${this.registeredTools.size}`);

        const oldToolCount = this.registeredTools.size;

        // Just track the tools, they will be registered to server instances dynamically
        for (const tool of tools) {
            const toolName = `${serviceName}_${tool.name}`;
            this.registeredTools.add(toolName);
        }
        console.log(`🎯 Tracked ${tools.length} tools for service ${serviceName}. Total unique tools: ${this.registeredTools.size}`);

        // Notify all active servers about tool list changes
        if (this.registeredTools.size !== oldToolCount) {
            this.notifyToolListChanged();
        }
    }

    // Utility methods for notifications - optimized with debouncing
    notifyToolListChanged() {
        // Use requestIdleCallback or setTimeout to batch notifications
        if (this.toolListChangeTimeout) {
            clearTimeout(this.toolListChangeTimeout);
        }

        this.toolListChangeTimeout = setTimeout(() => {
            const toolListHash = this.getToolListHash();
            if (toolListHash !== this.lastToolListHash) {
                this.lastToolListHash = toolListHash;
                // Send to all servers in parallel for better performance
                Promise.all(
                    Array.from(this.activeServers).map(server =>
                        Promise.resolve().then(() => server.sendToolListChanged()).catch(error =>
                            console.error('Error notifying tool list changed:', error.message)
                        )
                    )
                );
                // Invalidate caches
                this.invalidateHealthCache();
            }
        }, 100); // 100ms debounce
    }

    notifyResourceListChanged() {
        if (this.resourceListChangeTimeout) {
            clearTimeout(this.resourceListChangeTimeout);
        }

        this.resourceListChangeTimeout = setTimeout(() => {
            const resourceListHash = this.getResourceListHash();
            if (resourceListHash !== this.lastResourceListHash) {
                this.lastResourceListHash = resourceListHash;
                Promise.all(
                    Array.from(this.activeServers).map(server =>
                        Promise.resolve().then(() => server.sendResourceListChanged()).catch(error =>
                            console.error('Error notifying resource list changed:', error.message)
                        )
                    )
                );
                this.invalidateHealthCache();
            }
        }, 100);
    }

    notifyPromptListChanged() {
        // Some MCP clients/servers do not advertise prompt notification capability.
        // To avoid fatal errors (assertNotificationCapability), skip sending prompt list changed notifications.
        // We keep this function as a no-op for stability.
        return;
    }

    getToolListHash() {
        return Array.from(this.registeredTools).sort().join(',');
    }

    getResourceListHash() {
        return Array.from(this.processes.keys()).filter(name =>
            this.processes.get(name).initialized
        ).sort().join(',');
    }

    getPromptListHash() {
        return Array.from(this.processes.keys()).filter(name =>
            this.processes.get(name).initialized
        ).sort().join(',');
    }

    sendLogToClients(level, message, data = null) {
        // Optimize logging - avoid JSON.stringify in hot path unless needed
        const logMessage = {
            level: level,
            data: data ? `${message} ${typeof data === 'string' ? data : JSON.stringify(data)}` : message,
            logger: 'mcp-launcher'
        };

        // Send to all servers in parallel
        Promise.all(
            Array.from(this.activeServers).map(server =>
                Promise.resolve().then(() => server.sendLoggingMessage(logMessage)).catch(() => {
                    // Ignore errors when sending logs to avoid infinite loops
                })
            )
        );
    }

    // Cache invalidation helpers
    invalidateHealthCache() {
        this.cachedHealthStatus = null;
        this.lastHealthStatusUpdate = 0;
    }

    invalidateServicesCache() {
        this.cachedServicesList = null;
        this.lastServicesListUpdate = 0;
    }

    convertToZodSchema(inputSchema) {
        // Convert JSON Schema to a ZodRawShape (object of Zod fields)
        if (!inputSchema || !inputSchema.properties) {
            return {};
        }

        const zodFields = {};

        for (const [fieldName, fieldSchema] of Object.entries(inputSchema.properties)) {
            try {
                let zodField;

                switch (fieldSchema.type) {
                    case 'string':
                        zodField = z.string();
                        break;
                    case 'number':
                        zodField = z.number();
                        break;
                    case 'integer':
                        zodField = z.number().int();
                        break;
                    case 'boolean':
                        zodField = z.boolean();
                        break;
                    case 'array':
                        if (fieldSchema.items?.type === 'string') {
                            zodField = z.array(z.string());
                        } else if (fieldSchema.items?.type === 'object') {
                            zodField = z.array(z.any());
                        } else {
                            zodField = z.array(z.any());
                        }
                        break;
                    case 'object':
                        zodField = z.any(); // For complex objects, just accept any
                        break;
                    default:
                        zodField = z.any();
                }

                // Add description if available
                if (fieldSchema.description) {
                    try {
                        zodField = zodField.describe(fieldSchema.description);
                    } catch (error) {
                        console.warn(`Failed to add description to field ${fieldName}:`, error.message);
                    }
                }

                // Make optional if not required - safer approach
                const isRequired = inputSchema.required && inputSchema.required.includes(fieldName);
                if (!isRequired) {
                    try {
                        zodField = zodField.optional();
                    } catch (error) {
                        console.warn(`Failed to make field ${fieldName} optional, using z.any():`, error.message);
                        zodField = z.any().optional();
                    }
                }

                zodFields[fieldName] = zodField;
            } catch (error) {
                console.error(`Error processing field ${fieldName}:`, error.message);
                // Fallback to z.any() for problematic fields
                zodFields[fieldName] = z.any().optional();
            }
        }

        return zodFields;
    }

    processServiceOutput(serviceName) {
        const service = this.processes.get(serviceName);
        if (!service) return;

        let buf = service.responseBuffer;

        const tryParseLineDelimited = () => {
            const parts = buf.split('\n');
            service.responseBuffer = parts.pop() || '';
            for (const line of parts) {
                const t = line.trim();
                if (!t) continue;
                try {
                    const response = JSON.parse(t);
                    this.handleServiceResponse(serviceName, response);
                } catch {}
            }
            return true;
        };

        // If buffer starts with Content-Length, parse framed messages; otherwise try JSONL
        const parseFramed = () => {
            let changed = false;
            while (true) {
                const idx = buf.indexOf('\r\n\r\n');
                const idxAlt = buf.indexOf('\n\n');
                const sep = idx >= 0 ? '\r\n\r\n' : (idxAlt >= 0 ? '\n\n' : null);
                const sepPos = sep ? buf.indexOf(sep) : -1;
                if (sepPos < 0) break;
                const header = buf.slice(0, sepPos);
                const m = header.match(/Content-Length:\s*(\d+)/i);
                if (!m) break;
                const len = parseInt(m[1]);
                const start = sepPos + sep.length;
                const body = buf.slice(start, start + len);
                if (body.length < len) break; // wait for full body
                try {
                    const response = JSON.parse(body);
                    this.handleServiceResponse(serviceName, response);
                } catch {}
                buf = buf.slice(start + len);
                changed = true;
            }
            service.responseBuffer = buf;
            return changed;
        };

        // Heuristic: if buffer contains 'Content-Length:', parse as framed, else JSONL
        if (/Content-Length:/i.test(buf)) {
            if (!parseFramed()) {
                // if framing incomplete, keep buffer; do nothing
            }
        } else {
            tryParseLineDelimited();
        }
    }

    handleServiceResponse(serviceName, response) {
        try {
            if (this.config.server?.log_level && this.config.server.log_level.toLowerCase() === 'debug') {
                DebugLogger.logMCPResponse(serviceName, response);
            }
        } catch {}
        if (response && response.id && this.pendingRequests.has(response.id)) {
            const pending = this.pendingRequests.get(response.id);
            clearTimeout(pending.timeout);
            pending.resolve(response);
            this.pendingRequests.delete(response.id);
        }
    }

    async waitForResponse(requestId, timeoutMs = 15000) {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.pendingRequests.delete(requestId);
                reject(new Error(`Request ${requestId} timed out after ${timeoutMs}ms`));
            }, timeoutMs);

            this.pendingRequests.set(requestId, {
                resolve,
                reject,
                timeout
            });
        });
    }

    async callTool(serviceName, toolName, parameters) {
        const service = this.processes.get(serviceName);
        if (!service || !service.initialized) {
            throw new Error(`Service ${serviceName} not available`);
        }

        const requestId = this.requestIdCounter++;
        const request = {
            jsonrpc: "2.0",
            id: requestId,
            method: "tools/call",
            params: {
                name: toolName,
                arguments: parameters
            }
        };
        const reqStr = JSON.stringify(request);
        DebugLogger.logMCPRequest(serviceName, request);
        this.writeMessage(serviceName, request);

        let response;
        let respStr = '';
        try {
            response = await this.waitForResponse(requestId, 30000);
            respStr = JSON.stringify(response || {});
            return response.result;
        } finally {
            try {
                // Update per-service statistics
                if (!this.stats) this.stats = { services: {} };
                if (!this.stats.services) this.stats.services = {};
                if (!this.stats.services[serviceName]) {
                    this.stats.services[serviceName] = { calls: 0, bytes_in: 0, bytes_out: 0, last_call: null };
                }
                const rec = this.stats.services[serviceName];
                rec.calls += 1;
                // bytes_out: bytes we sent to the service (request)
                rec.bytes_out += Buffer.byteLength(reqStr + '\n');
                // bytes_in: bytes we received from the service (response)
                rec.bytes_in += Buffer.byteLength(respStr);
                rec.last_call = new Date().toISOString();
                this.saveStats();
            } catch (e) {
                console.warn('Failed to update/save stats:', e.message);
            }
            if (response && response.error) {
                // Re-throw after stats saved
                throw new Error(response.error.message || 'Tool call failed');
            }
        }
    }

    // Create the persistent MCP server instance
    createServer() {
        const server = new McpServer({
            name: "dynamic-mcp-bridge",
            version: "1.0.0",
        });

        // Track this server for notifications - only one persistent instance now
        this.activeServers.add(server);

        // Register all tools from all services (cached registration - no verbose logging)
        this.registerAllToolsCached(server);

        // Add specific resources for each service dynamically
        for (const [serviceName, service] of this.processes) {
            if (service.initialized) {
                server.resource(`mcp://${serviceName}/`, `${serviceName} service resources`, "application/json", async (uri) => {
                    return {
                        uri: uri,
                        name: `${serviceName} Service Resource`,
                        description: `Data from ${serviceName} service`,
                        content: JSON.stringify({
                            serviceName: serviceName,
                            tools: service.tools.map(t => ({ name: t.name, description: t.description })),
                            status: "initialized",
                            timestamp: new Date().toISOString()
                        }, null, 2)
                    };
                });
            }
        }

        // (Prompts were removed to avoid schema compatibility issues)

        // Note: Advanced handlers like completion and roots would need to be implemented
        // using server.server.setRequestHandler() with appropriate schemas, but are
        // not essential for basic MCP functionality

        // No cleanup needed for persistent server

        return server;
    }

    async handleMCPRequest(req, res) {
        const requestId = req.requestId || 'unknown';
        const startTime = req.startTime || Date.now();

        try {
            console.log(`[${new Date().toISOString()}] [REQUEST_${requestId}] ========== MCP PROCESSING ==========`);

            // Use the persistent server and transport - much more efficient!
            if (!this.mcpServer || !this.transport) {
                throw new Error('MCP server not initialized');
            }

            // Override res.write to capture SSE chunks from StreamableHTTPTransport
            const originalWrite = res.write;
            let chunkCount = 0;
            res.write = function (chunk, encoding) {
                chunkCount++;
                const responseTime = Date.now() - startTime;
                const responseTimestamp = new Date().toISOString();

                // Parse the chunk to extract meaningful data
                const chunkStr = chunk.toString();
                let logData = chunkStr;

                // Try to extract JSON from SSE data: lines
                if (chunkStr.includes('data: ')) {
                    const dataLines = chunkStr.split('\n').filter(line => line.startsWith('data: '));
                    if (dataLines.length > 0) {
                        logData = dataLines.map(line => line.substring(6)).join('\n');
                    }
                }

                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ========== SSE CHUNK ${chunkCount} ==========`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Response Time: ${responseTime}ms`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Status: ${res.statusCode}`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Chunk Size: ${chunk.length} bytes`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Data: ${logData.substring(0, 1000)}${logData.length > 1000 ? '...' : ''}`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ================================================`);

                return originalWrite.call(this, chunk, encoding);
            };

            // Use the persistent transport - no need to connect again!
            await this.transport.handleRequest(req, res, req.body);

        } catch (error) {
            const responseTime = Date.now() - startTime;
            const responseTimestamp = new Date().toISOString();

            console.error(`[${responseTimestamp}] [RESPONSE_${requestId}] ========== ERROR RESPONSE ==========`);
            console.error(`[${responseTimestamp}] [RESPONSE_${requestId}] Response Time: ${responseTime}ms`);
            console.error(`[${responseTimestamp}] [RESPONSE_${requestId}] Error:`, error.message);
            console.error(`[${responseTimestamp}] [RESPONSE_${requestId}] ================================================`);

            console.error("Error handling request:", error);
            if (!res.headersSent) {
                res.status(500).json({
                    error: 'Internal server error'
                });
            }
        }
    };

    async startAllServices() {
        console.log('🚀 Starting dynamic MCP bridge...');
        console.log(`📋 Services to start: ${Object.keys(this.services).join(", ")}`);

        for (const [serviceName, serviceConfig] of Object.entries(this.services)) {
            try {
                if (this.failedServices.has(serviceName)) {
                    console.log(`⏭️  Not auto-starting failed service: ${serviceName}`);
                    continue;
                }
                await this.startService(serviceName, serviceConfig);
                this.sendLogToClients('info', `Successfully started service: ${serviceName}`);
            } catch (error) {
                console.error(`❌ Failed to start ${serviceName}:`, error.message);
                this.sendLogToClients('error', `Failed to start service ${serviceName}: ${error.message}`);
                this.failedServices.add(serviceName);
            }
        }

        // Wait a bit for all tools to be fully registered
        await new Promise(resolve => setTimeout(resolve, 2000));
        console.log('🎉 All services started! Tools registered dynamically.');
        console.log(`🎯 Total tools registered with MCP server: ${this.registeredTools.size}`);
        this.sendLogToClients('info', `MCP Bridge started with ${this.registeredTools.size} tools from ${this.processes.size} services`);
    }

    // Add health monitoring with caching
    getHealthStatus() {
        const now = Date.now();

        // Return cached result if still valid
        if (this.cachedHealthStatus && (now - this.lastHealthStatusUpdate) < this.healthStatusCacheTTL) {
            return this.cachedHealthStatus;
        }

        // Compute new health status
        const services = {};
        for (const [serviceName, service] of this.processes) {
            services[serviceName] = {
                initialized: service.initialized,
                toolCount: service.tools ? service.tools.length : 0,
                pid: service.proc ? service.proc.pid : null,
                uptime: service.startTime ? now - service.startTime : 0
            };
        }

        this.cachedHealthStatus = {
            status: this.skipMcpLoading ? 'debug-skip' : 'healthy',
            totalTools: this.registeredTools.size,
            totalServices: this.processes.size,
            activeConnections: this.activeServers.size,
            services: services,
            timestamp: new Date().toISOString(),
            skipMcpServerLoading: !!this.skipMcpLoading
        };

        this.lastHealthStatusUpdate = now;
        return this.cachedHealthStatus;
    }

    // Add service restart capability
    async restartService(serviceName) {
        console.log(`🔄 Restarting service: ${serviceName}`);

        // Stop existing service
        const existingService = this.processes.get(serviceName);
        if (existingService && existingService.proc) {
            existingService.proc.kill();
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Start service again
        const serviceConfig = this.services[serviceName];
        if (serviceConfig) {
            try {
                // Clear failure flag on manual restart
                if (this.failedServices.has(serviceName)) this.failedServices.delete(serviceName);
                await this.startService(serviceName, serviceConfig);
                this.sendLogToClients('info', `Successfully restarted service: ${serviceName}`);
                return true;
            } catch (error) {
                console.error(`❌ Failed to restart ${serviceName}:`, error.message);
                this.sendLogToClients('error', `Failed to restart service ${serviceName}: ${error.message}`);
                return false;
            }
        }

        return false;
    }

    // Get services list with caching
    getServicesList() {
        const now = Date.now();

        // Return cached result if still valid
        if (this.cachedServicesList && (now - this.lastServicesListUpdate) < this.servicesListCacheTTL) {
            return this.cachedServicesList;
        }

        // Compute new services list
        const services = {};
        for (const [name, service] of this.processes) {
            services[name] = {
                initialized: service.initialized,
                toolCount: service.tools ? service.tools.length : 0,
                uptime: now - service.startTime
            };
        }

        this.cachedServicesList = services;
        this.lastServicesListUpdate = now;
        return services;
    }

    setupRoutes() {
        this.router.post("/message", async (req, res) => {
            this.handleMCPRequest(req, res)
        });
        this.router.post("/", async (req, res) => {
            this.handleMCPRequest(req, res)
        });

        // Add health endpoint for monitoring
        this.router.get("/health", (_req, res) => {
            res.json(this.getHealthStatus());
        });

        // Add service management endpoints
        this.router.post("/restart/:serviceName", async (req, res) => {
            const serviceName = req.params.serviceName;
            const success = await this.restartService(serviceName);
            res.json({
                success,
                message: success ? `Service ${serviceName} restarted` : `Failed to restart ${serviceName}`
            });
        });

        this.router.get("/services", (_req, res) => {
            res.json(this.getServicesList());
        });

        console.log("MCP launcher routes initialized");
    }

    getRouter() {
        return this.router;
    }
}
