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

        const mcpServerNames = Object.values(this.services).map(service => service.name).join(", ");
        console.log("MCP servers loaded from configuration: ", mcpServerNames);

        console.log("🔧 Starting MCP Bridge services...");
        // Start all backend services and register their tools
        await this.startAllServices()
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
            serviceName
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
            } else {
                console.log(`⚠️  ${serviceName} initialized but no tools found`);
            }
        } catch (error) {
            console.error(`❌ Failed to initialize ${serviceName}:`, error.message);
        }
    }

    registerServiceTools(serviceName, tools) {
        console.log(`🔧 registerServiceTools called for ${serviceName} with ${tools.length} tools. Current registered count: ${this.registeredTools.size}`);
        // Just track the tools, they will be registered to server instances dynamically
        for (const tool of tools) {
            const toolName = `${serviceName}_${tool.name}`;
            this.registeredTools.add(toolName);
        }
        console.log(`🎯 Tracked ${tools.length} tools for service ${serviceName}. Total unique tools: ${this.registeredTools.size}`);
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

    // Create a new server instance for each request (stateless mode)
    createServer() {
        const server = new McpServer({
            name: "dynamic-mcp-bridge",
            version: "1.0.0",
        });
        
        // Register all tools from all services (cached registration - no verbose logging)
        this.registerAllToolsCached(server);
        
        // Add resources handler
        server.resource("*", "List all available resources", "application/json", async () => {
            const resources = [];
            // Add resources from all services if they support it
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
        
        // Add prompts handler  
        server.prompt("*", "List all available prompts", async () => {
            const prompts = [];
            // Add prompts from all services if they support it
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
        
        return server;
    }    

    async handleMCPRequest(req, res) {
        const requestId = req.requestId || 'unknown';
        const startTime = req.startTime || Date.now();

        try {
            console.log(`[${new Date().toISOString()}] [REQUEST_${requestId}] ========== MCP PROCESSING ==========`);

            // In stateless mode, create a new instance of transport and server for each request
            // to ensure complete isolation. A single instance would cause request ID collisions
            // when multiple clients connect concurrently.
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: undefined, // Disable session management for stateless mode
                enableJsonResponse: false // Use SSE streaming
            });

            const server = this.createServer();

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

            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);

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
        console.log(`📋 Services to start: ${Object.values(this.services).map(service => service.name).join(", ")}`);

        for (const [serviceName, command] of Object.entries(this.services)) {
            try {
                await this.startService(serviceName, command);
            } catch (error) {
                console.error(`❌ Failed to start ${serviceName}:`, error.message);
            }
        }

        // Wait a bit for all tools to be fully registered
        await new Promise(resolve => setTimeout(resolve, 2000));
        console.log('🎉 All services started! Tools registered dynamically.');
        console.log(`🎯 Total tools registered with MCP server: ${this.registeredTools.size}`);
    }

    setupRoutes() {
        this.router.post("/message", async (req, res) => {
            this.handleMCPRequest(req, res)
        });
        this.router.post("/", async (req, res) => {
            this.handleMCPRequest(req, res)
        });
        console.log("MCP launcher routes initialized");
    }

    getRouter() {
        return this.router;
    }
}