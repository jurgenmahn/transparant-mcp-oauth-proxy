import express from 'express';
import fs from 'fs';
import { DashboardService } from './services/dashboard-service.js';
import { LauncherProxyService } from './services/launcher-proxy-service.js';
import { OAuthProxyService } from './services/oauth-proxy-service.js';
import YAML from 'yaml';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

class MCPServer {
    constructor() {

        const __filename = fileURLToPath(import.meta.url);
        this.appPath = dirname(__filename);

        this.app = express();
        this.config = {};
        this.services = {};
        this.loadConfig();
    }

    loadConfig() {
        try {
            this.config = YAML.parse(fs.readFileSync(this.appPath + '/config/local.yaml', 'utf-8'));
            // Set port from config if available
            if (this.config.server_port) {
                this.port = this.config.server_port;
            } else {
                this.port = 3000;
            }
        } catch (error) {
            console.error('Error loading MCP server config:', error);
            console.log('Using default port 3000');
            this.port = 3000;
        }
    }    
    
    async setupMiddleware() {
        this.app.use(express.json());

        // Handle CORS and security headers
        this.app.use((req, res, next) => {
            const origin = req.headers.origin;
            res.setHeader('Access-Control-Allow-Origin', origin || 'http://localhost');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Mcp-Session-Id');
            res.setHeader('Access-Control-Allow-Credentials', 'true');

            if (req.method === 'OPTIONS') {
                return res.sendStatus(200);
            }
            next();
        });      

        // Enhanced debug logging middleware
        this.app.use((req, res, next) => {
            const timestamp = new Date().toISOString();
            const requestId = Math.random().toString(36).substring(2, 11);

            // Log incoming request
            console.log(`[${timestamp}] [REQUEST_${requestId}] ========== INCOMING REQUEST ==========`);
            console.log(`[${timestamp}] [REQUEST_${requestId}] Method: ${req.method}`);
            console.log(`[${timestamp}] [REQUEST_${requestId}] URL: ${req.url}`);
            console.log(`[${timestamp}] [REQUEST_${requestId}] Headers:`, JSON.stringify(req.headers, null, 2));
            if (req.body && Object.keys(req.body).length > 0) {
                console.log(`[${timestamp}] [REQUEST_${requestId}] Body:`, JSON.stringify(req.body, null, 2));
            }
            console.log(`[${timestamp}] [REQUEST_${requestId}] Query:`, JSON.stringify(req.query, null, 2));

            // Store request ID for response logging
            req.requestId = requestId;
            req.startTime = Date.now();

            // Override res.json to log responses
            const originalJson = res.json;
            res.json = function (body) {
                const responseTime = Date.now() - req.startTime;
                const responseTimestamp = new Date().toISOString();

                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ========== OUTGOING RESPONSE ==========`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Status: ${res.statusCode}`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Response Time: ${responseTime}ms`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Headers:`, JSON.stringify(res.getHeaders(), null, 2));
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Body:`, JSON.stringify(body, null, 2));
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ================================================`);

                return originalJson.call(this, body);
            };

            // Override res.send to log text responses
            const originalSend = res.send;
            res.send = function (body) {
                const responseTime = Date.now() - req.startTime;
                const responseTimestamp = new Date().toISOString();

                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ========== OUTGOING RESPONSE ==========`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Status: ${res.statusCode}`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Response Time: ${responseTime}ms`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Headers:`, JSON.stringify(res.getHeaders(), null, 2));
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Body: ${body}`);
                console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ================================================`);

                return originalSend.call(this, body);
            };

            // Override res.end to log responses without explicit body
            const originalEnd = res.end;
            res.end = function (chunk, encoding) {
                if (!res.headersSent && chunk) {
                    const responseTime = Date.now() - req.startTime;
                    const responseTimestamp = new Date().toISOString();

                    console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ========== OUTGOING RESPONSE ==========`);
                    console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Status: ${res.statusCode}`);
                    console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Response Time: ${responseTime}ms`);
                    console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Headers:`, JSON.stringify(res.getHeaders(), null, 2));
                    console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Chunk: ${chunk}`);
                    console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ================================================`);
                }

                return originalEnd.call(this, chunk, encoding);
            };

            next();
        });


        this.app.use(express.urlencoded({ extended: true }));
        
        // Ensure query parsing is enabled
        this.app.use((req, res, next) => {
            // Express should handle this automatically, but let's make sure
            if (!req.query && req.url.includes('?')) {
                const url = new URL(req.url, `http://${req.headers.host}`);
                req.query = Object.fromEntries(url.searchParams);
            }
            next();
        });
        
        this.app.use(express.static('public'));
        this.app.use('/static', express.static('templates'));
    }
    
    async initializeServices() {

        console.log('📋 Creating services...');
        console.log('Application path: ', this.appPath);

        this.services.dashboard = new DashboardService(this.appPath);
        this.services.launcherProxy = new LauncherProxyService(this.appPath);
        this.services.oauthProxy = new OAuthProxyService(this.appPath);

        try {
            // Initialize Dashboard Service (already created)
            console.log('  📊 Initializing Dashboard Service...');
            await this.services.dashboard.initialize();
            console.log('  ✅ Dashboard Service ready');
            
            // Initialize Launcher Proxy Service (already created)
            console.log('  🚀 Initializing Launcher Proxy Service...');
            await this.services.launcherProxy.initialize();
            console.log('  ✅ Launcher Proxy Service ready');
            
            // Initialize OAuth Proxy Service (already created)
            console.log('  🔐 Initializing OAuth Proxy Service...');
            await this.services.oauthProxy.initialize();
            console.log('  ✅ OAuth Proxy Service ready');
            
            console.log('✅ All services initialized successfully');
        } catch (error) {
            console.error('❌ Error initializing services:', error);
            throw error;
        }
    }
    
    async setupServiceRoutes() {
        // Health check - make it very specific and first
        this.app.get('/health', (req, res) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                status: 'healthy', 
                services: Object.keys(this.services),
                timestamp: new Date().toISOString()
            }));
        });
        
        // Dashboard routes (prefix: /dashboard)
        this.app.use('/dashboard', this.services.dashboard.getRouter());
        
        // OAuth Proxy routes - Mount only once to avoid duplicates
        // Standard OAuth2 endpoints (expected by clients)
        this.app.use('/login', this.services.oauthProxy.getLoginRouter());
        this.app.use('/consent', this.services.oauthProxy.getConsentRouter());
        this.app.use('/oauth', this.services.oauthProxy.getRouter());
        
        
        // Launcher Proxy routes - Mount only at root to handle both /message and / 
        this.app.use("/", this.services.launcherProxy.getRouter());

        // Fallback route
        this.app.use('*', (req, res) => {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                error: 'Route not found',
                path: req.originalUrl
            }));
        });

        console.log("registered routes");
        this.app._router.stack.forEach(middleware => {
        if (middleware.route) {
            console.log(`${Object.keys(middleware.route.methods)[0].toUpperCase()} ${middleware.route.path}`);
        } else if (middleware.name === 'router') {
            middleware.handle.stack.forEach(handler => {
            if (handler.route) {
                console.log(`${Object.keys(handler.route.methods)[0].toUpperCase()} ${middleware.regexp.source.replace('\\/?(?=\\/|$)', '').replace(/\\\//g, '/')}${handler.route.path}`);
            }
            });
        }
        });        
    }
    
    async start() {
        try {
            console.log('🚀 Starting MCP Server...');
            
            // Start HTTP server first
            console.log('🌐 Starting HTTP server on port', this.port);
            this.server = this.app.listen(this.port, async () => {
                
                // Initialize services in the background after server is listening
                console.log('📋 Initializing services in background...');
                try {
                    await this.setupMiddleware();    
                    console.log('✅ Middleware ready');
                    await this.initializeServices();
                    console.log('✅ Services ready');
                    await this.setupServiceRoutes();
                    console.log('✅ Service routes ready');
                } catch (error) {
                    console.error('❌ Error initializing services in background:', error);
                }
            });
            
            // Graceful shutdown
            process.on('SIGTERM', () => this.shutdown());
            process.on('SIGINT', () => this.shutdown());
            
        } catch (error) {
            console.error('Failed to start server:', error);
            process.exit(1);
        }
    }
    
    async shutdown() {
        console.log('Shutting down MCP Unified Server...');
        
        // Shutdown services
        for (const [name, service] of Object.entries(this.services)) {
            try {
                if (service.shutdown) {
                    await service.shutdown();
                    console.log(`${name} service shut down`);
                }
            } catch (error) {
                console.error(`Error shutting down ${name} service:`, error);
            }
        }
        
        // Close HTTP server
        if (this.server) {
            this.server.close(() => {
                console.log('HTTP server closed');
                process.exit(0);
            });
        } else {
            process.exit(0);
        }
    }
}

// Start server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
    const server = new MCPServer();
    server.start();
}

export { MCPServer };