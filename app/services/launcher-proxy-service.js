import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { spawn } from "child_process";
import express from "express";
import fs from "fs";
import YAML from "yaml";

export class LauncherProxyService {
    constructor() {
        this.sseRouter = express.Router();
        this.apiRouter = express.Router();
        this.mainRouter = express.Router();
        this.config = {};
        this.services = new Map();
        this.server = null;
        this.childProcesses = [];
        
        this.setupRoutes();
    }
    
    async initialize() {
        await this.loadConfig();
        await this.initializeMCPServer();
        console.log('Launcher Proxy Service initialized');
    }
    
    async loadConfig() {
        try {
            this.config = YAML.parse(fs.readFileSync('./config/local.yaml', 'utf-8'));
        } catch (error) {
            console.error('Error loading launcher proxy config:', error);
            throw error;
        }
    }
    
    async initializeMCPServer() {
        // Create MCP server instance
        this.server = new McpServer({
            name: "mcp-launcher-proxy",
            version: "1.0.0"
        });
        
        // Parse services configuration
        const services = this.parseServices(this.config.mcp_services || []);
        
        // Initialize child processes for each service
        for (const [serviceName, serviceConfig] of Object.entries(services)) {
            await this.startChildService(serviceName, serviceConfig);
        }
        
        // Dynamic tool discovery and registration
        await this.discoverAndRegisterTools();
        
        console.log(`MCP Launcher Proxy initialized with ${this.services.size} services`);
    }
    
    // Debug logging utility
    static log(category, message, data = null) {
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] [${category}] ${message}`);
        if (data) {
            console.log(`[${timestamp}] [${category}] Data:`, JSON.stringify(data, null, 2));
        }
    }
    
    // Parse service configurations - support both old and new formats
    parseServices(mcpServicesConfig) {
        const services = {};
        
        if (Array.isArray(mcpServicesConfig)) {
            // New array format with name, startup_command, and options
            mcpServicesConfig.forEach(service => {
                if (service.name && service.startup_command) {
                    // Parse startup_command - it can be a string with quoted arguments
                    const commandParts = this.parseCommandString(service.startup_command);
                    
                    services[service.name] = {
                        command: commandParts[0], // First part is the command
                        args: [...commandParts.slice(1), ...(service.options || [])] // Merge command args with options
                    };
                }
            });
        } else if (typeof mcpServicesConfig === 'object') {
            // Legacy format - each service is an array of command parts
            Object.entries(mcpServicesConfig).forEach(([name, commandArray]) => {
                if (Array.isArray(commandArray) && commandArray.length > 0) {
                    services[name] = {
                        command: commandArray[0], // First element is the command
                        args: commandArray.slice(1) // Rest are arguments
                    };
                } else if (typeof commandArray === 'string') {
                    // Legacy string format
                    services[name] = {
                        command: commandArray,
                        args: []
                    };
                }
            });
        }
        
        return services;
    }
    
    // Parse command string that may contain quoted arguments
    parseCommandString(commandString) {
        const parts = [];
        let current = '';
        let inQuotes = false;
        let quoteChar = '';
        
        for (let i = 0; i < commandString.length; i++) {
            const char = commandString[i];
            
            if (!inQuotes && (char === '"' || char === "'")) {
                inQuotes = true;
                quoteChar = char;
            } else if (inQuotes && char === quoteChar) {
                inQuotes = false;
                quoteChar = '';
            } else if (!inQuotes && char === ' ') {
                if (current) {
                    parts.push(current);
                    current = '';
                }
            } else {
                current += char;
            }
        }
        
        if (current) {
            parts.push(current);
        }
        
        return parts;
    }
    
    // Start child service process
    async startChildService(serviceName, serviceConfig) {
        return new Promise((resolve, reject) => {
            try {
                LauncherProxyService.log('SERVICE_START', `Starting ${serviceName}`, { command: serviceConfig.command, args: serviceConfig.args });
                
                const child = spawn(serviceConfig.command, serviceConfig.args, {
                    stdio: ['pipe', 'pipe', 'pipe'],
                    cwd: process.cwd()
                });
                
                this.childProcesses.push(child);
                
                child.on('error', (error) => {
                    LauncherProxyService.log('SERVICE_ERROR', `Service ${serviceName} error: ${error.message}`);
                    reject(error);
                });
                
                child.on('exit', (code) => {
                    LauncherProxyService.log('SERVICE_EXIT', `Service ${serviceName} exited with code ${code}`);
                    this.services.delete(serviceName);
                });
                
                // Store service info
                this.services.set(serviceName, {
                    name: serviceName,
                    process: child,
                    tools: new Map(),
                    config: serviceConfig
                });
                
                // Give the service time to start
                setTimeout(() => {
                    LauncherProxyService.log('SERVICE_READY', `Service ${serviceName} ready`);
                    resolve();
                }, 1000);
                
            } catch (error) {
                LauncherProxyService.log('SERVICE_START_ERROR', `Failed to start ${serviceName}: ${error.message}`);
                reject(error);
            }
        });
    }
    
    // Discover and register tools from all services
    async discoverAndRegisterTools() {
        for (const [serviceName, serviceInfo] of this.services) {
            try {
                await this.discoverServiceTools(serviceName, serviceInfo);
            } catch (error) {
                LauncherProxyService.log('TOOL_DISCOVERY_ERROR', `Failed to discover tools for ${serviceName}: ${error.message}`);
            }
        }
    }
    
    // Discover tools from a specific service
    async discoverServiceTools(serviceName, serviceInfo) {
        return new Promise((resolve, reject) => {
            const listToolsRequest = {
                jsonrpc: "2.0",
                id: `discover_${serviceName}_${Date.now()}`,
                method: "tools/list"
            };
            
            LauncherProxyService.log('MCP_OUT', `→ ${serviceName}`, listToolsRequest);
            
            serviceInfo.process.stdin.write(JSON.stringify(listToolsRequest) + '\n');
            
            const timeout = setTimeout(() => {
                reject(new Error(`Tool discovery timeout for ${serviceName}`));
            }, 10000);
            
            const handleResponse = (data) => {
                try {
                    const lines = data.toString().split('\n').filter(line => line.trim());
                    
                    for (const line of lines) {
                        try {
                            const response = JSON.parse(line);
                            
                            if (response.id === listToolsRequest.id) {
                                clearTimeout(timeout);
                                serviceInfo.process.stdout.removeListener('data', handleResponse);
                                
                                LauncherProxyService.log('MCP_IN', `← ${serviceName}`, response);
                                
                                if (response.result && response.result.tools) {
                                    this.registerToolsForService(serviceName, response.result.tools);
                                    resolve(response.result.tools);
                                } else {
                                    resolve([]);
                                }
                                return;
                            }
                        } catch (parseError) {
                            // Skip invalid JSON lines
                        }
                    }
                } catch (error) {
                    LauncherProxyService.log('TOOL_DISCOVERY_PARSE_ERROR', `Parse error for ${serviceName}: ${error.message}`);
                }
            };
            
            serviceInfo.process.stdout.on('data', handleResponse);
        });
    }
    
    // Register tools for a service with prefixed names
    registerToolsForService(serviceName, tools) {
        const service = this.services.get(serviceName);
        if (!service) return;
        
        tools.forEach(tool => {
            const prefixedName = `${serviceName}_${tool.name}`;
            service.tools.set(prefixedName, tool);
            
            // Register with MCP server
            this.server.setRequestHandler({ method: `tools/call`, params: { name: prefixedName } }, async (request) => {
                return await this.handleToolCall(serviceName, tool.name, request.params.arguments || {});
            });
            
            LauncherProxyService.log('TOOL_REGISTERED', `Registered ${prefixedName} from ${serviceName}`);
        });
        
        // Update tools list handler
        this.updateToolsListHandler();
    }
    
    // Update the tools/list handler with all discovered tools
    updateToolsListHandler() {
        const allTools = [];
        
        for (const [serviceName, service] of this.services) {
            for (const [prefixedName, tool] of service.tools) {
                allTools.push({
                    name: prefixedName,
                    description: `[${serviceName}] ${tool.description || ''}`,
                    inputSchema: tool.inputSchema || { type: "object", properties: {} }
                });
            }
        }
        
        this.server.setRequestHandler({ method: "tools/list" }, async () => {
            return { tools: allTools };
        });
    }
    
    // Handle tool call by forwarding to appropriate service
    async handleToolCall(serviceName, toolName, args) {
        const service = this.services.get(serviceName);
        if (!service) {
            throw new Error(`Service ${serviceName} not found`);
        }
        
        return new Promise((resolve, reject) => {
            const toolCallRequest = {
                jsonrpc: "2.0",
                id: `tool_${serviceName}_${toolName}_${Date.now()}`,
                method: "tools/call",
                params: {
                    name: toolName,
                    arguments: args
                }
            };
            
            LauncherProxyService.log('MCP_OUT', `→ ${serviceName}`, toolCallRequest);
            
            service.process.stdin.write(JSON.stringify(toolCallRequest) + '\n');
            
            const timeout = setTimeout(() => {
                reject(new Error(`Tool call timeout for ${serviceName}/${toolName}`));
            }, 30000);
            
            const handleResponse = (data) => {
                try {
                    const lines = data.toString().split('\n').filter(line => line.trim());
                    
                    for (const line of lines) {
                        try {
                            const response = JSON.parse(line);
                            
                            if (response.id === toolCallRequest.id) {
                                clearTimeout(timeout);
                                service.process.stdout.removeListener('data', handleResponse);
                                
                                LauncherProxyService.log('MCP_IN', `← ${serviceName}`, response);
                                
                                if (response.error) {
                                    reject(new Error(response.error.message || 'Tool call failed'));
                                } else {
                                    resolve(response.result || {});
                                }
                                return;
                            }
                        } catch (parseError) {
                            // Skip invalid JSON lines
                        }
                    }
                } catch (error) {
                    LauncherProxyService.log('TOOL_CALL_PARSE_ERROR', `Parse error for ${serviceName}/${toolName}: ${error.message}`);
                }
            };
            
            service.process.stdout.on('data', handleResponse);
        });
    }
    
    setupRoutes() {
        // SSE endpoint
        this.sseRouter.get('/', (req, res) => {
            LauncherProxyService.log('HTTP_IN', `SSE connection from ${req.ip}`);
            
            res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Cache-Control'
            });
            
            const transport = new StreamableHTTPServerTransport(res);
            this.server.connect(transport);
            
            req.on('close', () => {
                LauncherProxyService.log('HTTP_OUT', 'SSE connection closed');
            });
        });
        
        // API endpoints
        this.apiRouter.get('/tools', async (_, res) => {
            try {
                const toolsList = await this.server.request({ method: "tools/list" }, {});
                res.json(toolsList);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        this.apiRouter.post('/tools/:toolName', async (req, res) => {
            try {
                const result = await this.server.request(
                    { method: "tools/call", params: { name: req.params.toolName } },
                    req.body
                );
                res.json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // Health check for launcher proxy
        this.mainRouter.get('/launcher/health', (_, res) => {
            const servicesStatus = {};
            for (const [name, service] of this.services) {
                servicesStatus[name] = {
                    running: service.process && !service.process.killed,
                    toolCount: service.tools.size
                };
            }
            
            res.json({
                status: 'healthy',
                services: servicesStatus,
                totalServices: this.services.size
            });
        });
        
        // Service management endpoints
        this.mainRouter.get('/launcher/services', (_, res) => {
            const servicesList = {};
            for (const [name, service] of this.services) {
                servicesList[name] = {
                    name: service.name,
                    running: service.process && !service.process.killed,
                    tools: Array.from(service.tools.keys()),
                    config: service.config
                };
            }
            res.json(servicesList);
        });
    }
    
    getSSERouter() {
        return this.sseRouter;
    }
    
    getAPIRouter() {
        return this.apiRouter;
    }
    
    getMainRouter() {
        return this.mainRouter;
    }
    
    async shutdown() {
        console.log('Launcher Proxy Service shutting down...');
        
        // Kill all child processes
        this.childProcesses.forEach(child => {
            if (child && !child.killed) {
                child.kill('SIGTERM');
            }
        });
        
        // Wait for processes to exit
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Force kill if still running
        this.childProcesses.forEach(child => {
            if (child && !child.killed) {
                child.kill('SIGKILL');
            }
        });
        
        this.services.clear();
        this.childProcesses = [];
        
        console.log('Launcher Proxy Service shut down complete');
    }
}