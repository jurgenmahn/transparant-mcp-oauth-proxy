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
        this.log('MCP_OUT', `→ ${serviceName}`, request);
    }

    static logMCPResponse(serviceName, response) {
        this.log('MCP_IN', `← ${serviceName}`, response);
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
    }

    async initialize() {
        await this.loadConfig();
        await this.initializeMCPServer();
        console.log('Launcher Proxy Service initialized');
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

        console.log("🔧 Starting MCP Bridge services...");
        // Start all backend services and register their tools
        await this.startAllServices();
        
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
                if (serviceConfig.name && serviceConfig.startup_command) {
                    // Parse startup_command string into array
                    const commandParts = serviceConfig.startup_command.split(/\s+/);

                    // Add options if present
                    let fullCommand = commandParts;
                    if (serviceConfig.options && Array.isArray(serviceConfig.options)) {
                        fullCommand = [...commandParts, ...serviceConfig.options];
                    }

                    services[serviceConfig.name] = fullCommand;
                }
            }
        } else if (typeof mcpServicesConfig === 'object' && mcpServicesConfig !== null) {
            // Old format: object with service names as keys and arrays as values
            for (const [serviceName, command] of Object.entries(mcpServicesConfig)) {
                if (Array.isArray(command)) {
                    services[serviceName] = command;
                }
            }
        }

        return services;
    }

    async startService(serviceName, command) {
        console.log(`🔧 Starting ${serviceName} service...`);

        const proc = spawn(command[0], command.slice(1), {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        const service = {
            proc,
            responseBuffer: '',
            initialized: false,
            tools: [],
            serviceName,
            startTime: Date.now()
        };

        this.processes.set(serviceName, service);

        // Handle stdout
        proc.stdout.on('data', (data) => {
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
        proc.on('close', (code) => {
            console.error(`[${serviceName}] ❌ Process exited with code ${code}`);
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
        await this.initializeService(serviceName);

        return service;
    }

    async initializeService(serviceName) {
        const service = this.processes.get(serviceName);
        if (!service) return;

        try {
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
            service.proc.stdin.write(JSON.stringify(initRequest) + '\n');
            await this.waitForResponse(initRequest.id);

            // Send tools/list
            const toolsRequest = {
                jsonrpc: "2.0",
                id: this.requestIdCounter++,
                method: "tools/list",
                params: {}
            };

            DebugLogger.logMCPRequest(serviceName, toolsRequest);
            service.proc.stdin.write(JSON.stringify(toolsRequest) + '\n');
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
        if (this.promptListChangeTimeout) {
            clearTimeout(this.promptListChangeTimeout);
        }
        
        this.promptListChangeTimeout = setTimeout(() => {
            const promptListHash = this.getPromptListHash();
            if (promptListHash !== this.lastPromptListHash) {
                this.lastPromptListHash = promptListHash;
                Promise.all(
                    Array.from(this.activeServers).map(server => 
                        Promise.resolve().then(() => server.sendPromptListChanged()).catch(error => 
                            console.error('Error notifying prompt list changed:', error.message)
                        )
                    )
                );
                this.invalidateHealthCache();
            }
        }, 100);
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
        // Convert JSON Schema to Zod schema dynamically
        if (!inputSchema || !inputSchema.properties) {
            return {};
        }

        const zodFields = {};

        for (const [fieldName, fieldSchema] of Object.entries(inputSchema.properties)) {
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
                zodField = zodField.describe(fieldSchema.description);
            }

            // Make optional if not required
            if (!inputSchema.required || !inputSchema.required.includes(fieldName)) {
                zodField = zodField.optional();
            }

            zodFields[fieldName] = zodField;
        }

        return zodFields;
    }

    processServiceOutput(serviceName) {
        const service = this.processes.get(serviceName);
        if (!service) return;

        const lines = service.responseBuffer.split('\n');
        service.responseBuffer = lines.pop() || '';

        for (const line of lines) {
            if (!line.trim()) continue;

            try {
                const response = JSON.parse(line);
                DebugLogger.logMCPResponse(serviceName, response);

                // Handle pending requests
                if (response.id && this.pendingRequests.has(response.id)) {
                    const pending = this.pendingRequests.get(response.id);
                    clearTimeout(pending.timeout);
                    pending.resolve(response);
                    this.pendingRequests.delete(response.id);
                }
            } catch (error) {
                // Not JSON, ignore
            }
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

        DebugLogger.logMCPRequest(serviceName, request);
        service.proc.stdin.write(JSON.stringify(request) + '\n');

        const response = await this.waitForResponse(requestId, 30000);

        if (response.error) {
            throw new Error(response.error.message || 'Tool call failed');
        }

        return response.result;
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
        
        // Add resources handler with template support
        server.resource("mcp://{serviceName}/", "Service-specific resources", "application/json", async (uri) => {
            const match = uri.match(/^mcp:\/\/([^\/]+)\//);
            if (!match) {
                throw new Error("Invalid resource URI");
            }
            
            const serviceName = match[1];
            const service = this.processes.get(serviceName);
            
            if (!service || !service.initialized) {
                throw new Error(`Service ${serviceName} not available`);
            }
            
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
        
        // Add general resources handler
        server.resource("*", "List all available resources", "application/json", async () => {
            const resources = [];
            for (const [serviceName, service] of this.processes) {
                if (service.initialized) {
                    resources.push({
                        uri: `mcp://${serviceName}/`,
                        name: `${serviceName.charAt(0).toUpperCase() + serviceName.slice(1)} Service`,
                        description: `Resources from ${serviceName} service`,
                        mimeType: "application/json"
                    });
                }
            }
            return resources;
        });
        
        // Add prompts handler with argument support
        server.prompt("help", "Get help for a specific service", {
            service: {
                type: "string",
                description: "The service name to get help for",
                required: true
            }
        }, async (args) => {
            const serviceName = args.service;
            const service = this.processes.get(serviceName);
            
            if (!service || !service.initialized) {
                throw new Error(`Service ${serviceName} not available`);
            }
            
            let helpText = `Help for ${serviceName} service:\n\n`;
            helpText += `Tools available:\n`;
            
            for (const tool of service.tools) {
                helpText += `- ${serviceName}_${tool.name}: ${tool.description}\n`;
            }
            
            return {
                messages: [{
                    role: "user",
                    content: {
                        type: "text",
                        text: helpText
                    }
                }]
            };
        });
        
        // Add general prompts handler
        server.prompt("*", "List all available prompts", async () => {
            const prompts = [];
            prompts.push({
                name: "help",
                description: "Get help for a specific service",
                arguments: [{
                    name: "service",
                    description: "The service name to get help for", 
                    required: true
                }]
            });
            
            for (const [serviceName, service] of this.processes) {
                if (service.initialized) {
                    prompts.push({
                        name: `${serviceName}_help`,
                        description: `Get help for ${serviceName} service tools`,
                        arguments: []
                    });
                }
            }
            return prompts;
        });
        
        // Add completion handler for auto-completion
        server.setCompletion(async (ref, argument) => {
            if (ref.type === "resource" && ref.uri.startsWith("mcp://")) {
                // Auto-complete service names
                const services = Array.from(this.processes.keys()).filter(name => 
                    this.processes.get(name).initialized
                );
                return {
                    completion: {
                        values: services.map(service => ({
                            value: service,
                            label: `${service} service`,
                            description: `Resources from ${service}`
                        }))
                    }
                };
            }
            
            if (ref.type === "prompt" && argument === "service") {
                // Auto-complete service names for help prompt
                const services = Array.from(this.processes.keys()).filter(name => 
                    this.processes.get(name).initialized
                );
                return {
                    completion: {
                        values: services.map(service => ({
                            value: service,
                            label: service,
                            description: `${service} service`
                        }))
                    }
                };
            }
            
            return { completion: { values: [] } };
        });
        
        // Add roots handler for workspace discovery
        server.setRoots(async () => {
            return [
                {
                    uri: "file:///workspace",
                    name: "MCP Workspace",
                    description: "Main workspace for MCP services"
                },
                {
                    uri: `mcp://services/`,
                    name: "MCP Services",
                    description: "Available MCP services and their resources"
                }
            ];
        });
        
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

        for (const [serviceName, command] of Object.entries(this.services)) {
            try {
                await this.startService(serviceName, command);
                this.sendLogToClients('info', `Successfully started service: ${serviceName}`);
            } catch (error) {
                console.error(`❌ Failed to start ${serviceName}:`, error.message);
                this.sendLogToClients('error', `Failed to start service ${serviceName}: ${error.message}`);
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
            status: 'healthy',
            totalTools: this.registeredTools.size,
            totalServices: this.processes.size,
            activeConnections: this.activeServers.size,
            services: services,
            timestamp: new Date().toISOString()
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
        const command = this.services[serviceName];
        if (command) {
            try {
                await this.startService(serviceName, command);
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