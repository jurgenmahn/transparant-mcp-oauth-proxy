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
        this.port = process.env.PORT || 3000;
        this.services = {};
        
        this.loadConfig();
        this.setupMiddleware();
        this.setupRoutes();
    }

    loadConfig() {
        try {
            this.config = YAML.parse(fs.readFileSync('./config/local.yaml', 'utf-8'));
            // Set port from config if available
            if (this.config.services?.oauth_proxy?.port) {
                this.port = this.config.services.oauth_proxy.port;
            }
        } catch (error) {
            console.error('Error loading MCP server config:', error);
            console.log('Using default port 3000');
        }
    }    
    
    setupMiddleware() {
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(express.static('public'));
        this.app.use('/static', express.static('templates'));
    }
    
    async initializeServices() {
        try {
            // Initialize Dashboard Service
            this.services.dashboard = new DashboardService();
            await this.services.dashboard.initialize();
            
            // Initialize Launcher Proxy Service
            this.services.launcherProxy = new LauncherProxyService();
            await this.services.launcherProxy.initialize();
            
            // Initialize OAuth Proxy Service  
            this.services.oauthProxy = new OAuthProxyService();
            await this.services.oauthProxy.initialize();
            
            console.log('All services initialized successfully');
        } catch (error) {
            console.error('Error initializing services:', error);
            process.exit(1);
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
        
        // Health check
        this.app.get('/health', (_, res) => {
            res.json({ 
                status: 'healthy', 
                services: Object.keys(this.services),
                timestamp: new Date().toISOString()
            });
        });
        
        // Dashboard routes (prefix: /dashboard)
        this.app.use('/dashboard', this.services.dashboard.getRouter());
        
        // Launcher Proxy routes (prefix: /mcp or root for SSE)
        this.app.use('/sse', this.services.launcherProxy.getSSERouter());
        this.app.use('/mcp', this.services.launcherProxy.getAPIRouter());
        this.app.use('/', this.services.launcherProxy.getMainRouter());
        
        // OAuth Proxy routes (prefix: /oauth)
        this.app.use('/oauth', this.services.oauthProxy.getRouter());
        this.app.use('/login', this.services.oauthProxy.getLoginRouter());
        this.app.use('/consent', this.services.oauthProxy.getConsentRouter());
        
        // Fallback route
        this.app.use('*', (req, res) => {
            res.status(404).json({ 
                error: 'Route not found',
                availableServices: ['dashboard', 'mcp', 'oauth'],
                path: req.originalUrl
            });
        });
    }
    
    async start() {
        try {
            await this.initializeServices();
            
            // Setup service routes after initialization
            this.setupServiceRoutes();
            
            this.server = this.app.listen(this.port, () => {
                console.log(`
╭─────────────────────────────────────────────────────────╮
│                   MCP Unified Server                    │
├─────────────────────────────────────────────────────────┤
│ Port: ${this.port.toString().padEnd(48)} │
│ Services:                                               │
│   • Dashboard:      http://localhost:${this.port}/dashboard      │
│   • MCP Proxy:      http://localhost:${this.port}/mcp           │
│   • SSE Endpoint:   http://localhost:${this.port}/sse           │
│   • OAuth:          http://localhost:${this.port}/oauth         │
│   • Health Check:   http://localhost:${this.port}/health        │
╰─────────────────────────────────────────────────────────╯
                `);
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