import express from 'express';
import fs from 'fs';
import { DashboardService } from './services/dashboard-service.js';
import { LauncherProxyService } from './services/launcher-proxy-service.js';
import { OAuthProxyService } from './services/oauth-proxy-service.js';
import YAML from 'yaml';

class MCPServer {
    constructor() {
        this.app = express();
        this.config = {};
        this.services = {};
        
        this.loadConfig();
        this.setupMiddleware();
        this.setupRoutes();
        this.initializeServiceStubs();
    }

    loadConfig() {
        try {
            this.config = YAML.parse(fs.readFileSync('./config/local.yaml', 'utf-8'));
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
    
    initializeServiceStubs() {
        // Create stub services immediately so routes can be set up
        console.log('📋 Creating service stubs...');
        
        // Create service instances but don't initialize them yet
        this.services.dashboard = new DashboardService();
        this.services.launcherProxy = new LauncherProxyService();
        this.services.oauthProxy = new OAuthProxyService();
        
        // Set up routes immediately with stub services
        this.setupServiceRoutes();
        console.log('✅ Service routes ready');
    }
    
    setupMiddleware() {
        this.app.use(express.json());
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
    
    setupRoutes() {
        // Health check
        this.app.get('/health', (_, res) => {
            res.json({ 
                status: 'healthy', 
                services: Object.keys(this.services),
                timestamp: new Date().toISOString()
            });
        });
        
        // Fallback route for uninitialized services
        this.app.use('*', (req, res) => {
            if (Object.keys(this.services).length === 0) {
                res.status(503).json({ 
                    error: 'Services are initializing',
                    message: 'Please wait for services to start'
                });
            } else {
                res.status(404).json({ 
                    error: 'Route not found',
                    availableServices: ['dashboard', 'mcp', 'oauth'],
                    path: req.originalUrl
                });
            }
        });
    }
    
    setupServiceRoutes() {
        // Clear existing routes except health and fallback
        this.app._router = express.Router();
        
        // Re-add middleware
        this.setupMiddleware();
        
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
        
        // OAuth Proxy routes - Mount both with and without /oauth prefix
        // Standard OAuth2 endpoints (expected by clients)
        this.app.use('/', this.services.oauthProxy.getRouter());
        this.app.use('/login', this.services.oauthProxy.getLoginRouter());
        this.app.use('/consent', this.services.oauthProxy.getConsentRouter());
        // Also mount with /oauth prefix for backwards compatibility
        this.app.use('/oauth', this.services.oauthProxy.getRouter());
        this.app.use('/oauth/login', this.services.oauthProxy.getLoginRouter());
        this.app.use('/oauth/consent', this.services.oauthProxy.getConsentRouter());
        
        // Launcher Proxy routes (prefix: /mcp or root for SSE)
        this.app.use('/sse', this.services.launcherProxy.getSSERouter());
        this.app.use('/mcp', this.services.launcherProxy.getAPIRouter());
        this.app.use('/launcher', this.services.launcherProxy.getMainRouter());
        
        // Root level MCP routes (for direct MCP access)
        this.app.use('/', this.services.launcherProxy.getAPIRouter());
        
        // Fallback route
        this.app.use('*', (req, res) => {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                error: 'Route not found',
                availableServices: ['dashboard', 'mcp', 'oauth'],
                path: req.originalUrl
            }));
        });
    }
    
    async start() {
        try {
            console.log('🚀 Starting MCP Server...');
            
            // Start HTTP server first
            console.log('🌐 Starting HTTP server on port', this.port);
            this.server = this.app.listen(this.port, async () => {
                console.log(`
╭─────────────────────────────────────────────────────────╮
│                   MCP Unified Server                    │
├─────────────────────────────────────────────────────────┤
│ Port: ${this.port.toString().padEnd(48)} │
│ Status: Starting services...                           │
│ Health Check:   http://localhost:${this.port}/health        │
╰─────────────────────────────────────────────────────────╯
                `);
                
                // Initialize services in the background after server is listening
                console.log('📋 Initializing services in background...');
                try {
                    await this.initializeServices();
                    
                    console.log(`
╭─────────────────────────────────────────────────────────╮
│                   MCP Unified Server                    │
├─────────────────────────────────────────────────────────┤
│ Port: ${this.port.toString().padEnd(48)} │
│ Status: ✅ All services ready!                          │
│ Services:                                               │
│   • Dashboard:      http://localhost:${this.port}/dashboard      │
│   • MCP Proxy:      http://localhost:${this.port}/mcp           │
│   • SSE Endpoint:   http://localhost:${this.port}/sse           │
│   • OAuth:          http://localhost:${this.port}/oauth         │
│   • Health Check:   http://localhost:${this.port}/health        │
╰─────────────────────────────────────────────────────────╯
                    `);
                } catch (error) {
                    console.error('❌ Error initializing services in background:', error);
                    console.log(`
╭─────────────────────────────────────────────────────────╮
│                   MCP Unified Server                    │
├─────────────────────────────────────────────────────────┤
│ Port: ${this.port.toString().padEnd(48)} │
│ Status: ⚠️  Basic server running, services failed       │
│ Health Check:   http://localhost:${this.port}/health        │
╰─────────────────────────────────────────────────────────╯
                    `);
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