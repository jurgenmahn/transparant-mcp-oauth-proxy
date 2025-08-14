import express from 'express';
import fs from 'fs';
import multer from 'multer';
import { DashboardService } from './services/dashboard-service.js';
import { LauncherProxyService } from './services/launcher-proxy-service.js';
import { UnifiedOAuthService } from './services/unified-oauth-service.js';
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
        this.debugRequests = new Map(); // Store debug data: requestId -> {request, response}
        this.maxDebugEntries = 1000; // Limit memory usage
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

    generateDebugHtml(debugData) {
        const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Server Debug Console</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .filters { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-input { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .btn { padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        .request-response { background: white; margin-bottom: 20px; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .request-header { background: #28a745; color: white; padding: 15px; display: flex; justify-content: space-between; align-items: center; }
        .response-header { background: #17a2b8; color: white; padding: 15px; display: flex; justify-content: space-between; align-items: center; }
        .method { font-weight: bold; padding: 4px 8px; border-radius: 4px; background: rgba(255,255,255,0.2); }
        .status { font-weight: bold; padding: 4px 8px; border-radius: 4px; }
        .status.success { background: #d4edda; color: #155724; }
        .status.error { background: #f8d7da; color: #721c24; }
        .status.redirect { background: #fff3cd; color: #856404; }
        .content { padding: 15px; }
        .content-row { display: flex; gap: 20px; }
        .content-col { flex: 1; }
        .json-viewer { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 15px; overflow-x: auto; font-family: 'Monaco', 'Menlo', monospace; font-size: 12px; white-space: pre-wrap; }
        .timing { font-size: 12px; opacity: 0.8; }
        .no-data { text-align: center; padding: 40px; color: #666; }
        .response-time { font-weight: bold; }
        .response-time.fast { color: #28a745; }
        .response-time.medium { color: #ffc107; }
        .response-time.slow { color: #dc3545; }
        .expand-btn { background: none; border: none; color: white; cursor: pointer; font-size: 16px; }
        .collapsible-content { display: none; }
        .expanded .collapsible-content { display: block; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐛 MCP Server Debug Console</h1>
        <p>Real-time HTTP request and response monitoring</p>
        
        <div class="filters">
            <input type="text" id="methodFilter" class="filter-input" placeholder="Filter by method (GET, POST...)" value="${new URLSearchParams(global.location?.search || '').get('method') || ''}">
            <input type="text" id="urlFilter" class="filter-input" placeholder="Filter by URL" value="${new URLSearchParams(global.location?.search || '').get('url') || ''}">
            <input type="text" id="statusFilter" class="filter-input" placeholder="Filter by status (200, 404...)" value="${new URLSearchParams(global.location?.search || '').get('status') || ''}">
            <input type="number" id="limitFilter" class="filter-input" placeholder="Limit (default: 100)" value="${new URLSearchParams(global.location?.search || '').get('limit') || ''}">
            <button onclick="applyFilters()" class="btn">Apply Filters</button>
            <button onclick="clearFilters()" class="btn" style="background: #6c757d;">Clear</button>
            <button onclick="location.reload()" class="btn" style="background: #28a745;">Refresh</button>
        </div>
    </div>

    <div id="requests">
        ${debugData.length === 0 ? '<div class="no-data">No requests captured yet. Make some requests to see debug data here.</div>' : ''}
        ${debugData.map(entry => this.generateRequestResponseHtml(entry)).join('')}
    </div>

    <script>
        function applyFilters() {
            const params = new URLSearchParams();
            const method = document.getElementById('methodFilter').value;
            const url = document.getElementById('urlFilter').value;
            const status = document.getElementById('statusFilter').value;
            const limit = document.getElementById('limitFilter').value;
            
            if (method) params.set('method', method);
            if (url) params.set('url', url);
            if (status) params.set('status', status);
            if (limit) params.set('limit', limit);
            
            window.location.search = params.toString();
        }
        
        function clearFilters() {
            window.location.search = '';
        }
        
        function toggleSection(button) {
            const requestResponse = button.closest('.request-response');
            requestResponse.classList.toggle('expanded');
        }
        
        // Auto-refresh removed per user request
    </script>
</body>
</html>`;
        return html;
    }

    generateRequestResponseHtml(entry) {
        const { request, response } = entry;
        const hasResponse = !!response;

        const getStatusClass = (status) => {
            if (status >= 200 && status < 300) return 'success';
            if (status >= 300 && status < 400) return 'redirect';
            return 'error';
        };

        const getResponseTimeClass = (time) => {
            if (time < 100) return 'fast';
            if (time < 500) return 'medium';
            return 'slow';
        };

        const formatJson = (obj) => {
            if (!obj) return 'null';
            return JSON.stringify(obj, null, 2);
        };

        const formatTimestamp = (timestamp) => {
            return new Date(timestamp).toLocaleString();
        };

        return `
            <div class="request-response">
                <div class="request-header">
                    <div>
                        <span class="method">${request.method}</span>
                        <strong>${request.url}</strong>
                        <div class="timing">${formatTimestamp(request.timestamp)}</div>
                    </div>
                    <button class="expand-btn" onclick="toggleSection(this)">▼</button>
                </div>
                
                ${hasResponse ? `
                <div class="response-header">
                    <div>
                        <span class="status ${getStatusClass(response.status)}">${response.status}</span>
                        <span class="response-time ${getResponseTimeClass(response.responseTime)}">${response.responseTime}ms</span>
                        <div class="timing">${formatTimestamp(response.timestamp)}</div>
                    </div>
                </div>
                ` : '<div class="response-header" style="background: #6c757d;"><div>No Response Yet</div></div>'}
                
                <div class="collapsible-content">
                    <div class="content">
                        <div class="content-row">
                            <div class="content-col">
                                <h4>📤 Request</h4>
                                <h5>Headers:</h5>
                                <div class="json-viewer">${formatJson(request.headers)}</div>
                                ${request.query && Object.keys(request.query).length > 0 ? `
                                <h5>Query Parameters:</h5>
                                <div class="json-viewer">${formatJson(request.query)}</div>
                                ` : ''}
                                ${request.body ? `
                                <h5>Body:</h5>
                                <div class="json-viewer">${formatJson(request.body)}</div>
                                ` : ''}
                            </div>
                            
                            ${hasResponse ? `
                            <div class="content-col">
                                <h4>📥 Response</h4>
                                <h5>Headers:</h5>
                                <div class="json-viewer">${formatJson(response.headers)}</div>
                                ${response.body ? `
                                <h5>Body (${response.type}):</h5>
                                <div class="json-viewer">${response.type === 'json' ? formatJson(response.body) : response.body}</div>
                                ` : ''}
                            </div>
                            ` : `
                            <div class="content-col">
                                <h4>📥 Response</h4>
                                <div class="no-data">Waiting for response...</div>
                            </div>
                            `}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    async setupMiddleware() {
        // Enable trust proxy to correctly identify secure connections behind reverse proxies
        this.app.set('trust proxy', true);
        this.app.use(express.json());

        if (this.config.server.log_level.toLowerCase() == "debug") {
            // Enhanced debug logging middleware
            this.app.use((req, res, next) => {
                // Skip debug logging for the debug endpoint itself
                if (req.url === '/debug' || req.url.startsWith('/debug?')) {
                    return next();
                }

                const timestamp = new Date().toISOString();
                const requestId = Math.random().toString(36).substring(2, 11);
                const startTime = Date.now();

                // Store request data for debug endpoint
                const requestData = {
                    id: requestId,
                    timestamp: timestamp,
                    startTime: startTime,
                    method: req.method,
                    url: req.url,
                    headers: { ...req.headers },
                    body: req.body ? JSON.parse(JSON.stringify(req.body)) : null,
                    query: { ...req.query }
                };

                // Log incoming request (keep existing console output)
                console.log(`[${timestamp}] [REQUEST_${requestId}] ========== INCOMING REQUEST ==========`);
                console.log(`[${timestamp}] [REQUEST_${requestId}] Method: ${req.method}`);
                console.log(`[${timestamp}] [REQUEST_${requestId}] URL: ${req.url}`);
                console.log(`[${timestamp}] [REQUEST_${requestId}] Headers:`, JSON.stringify(req.headers, null, 2));
                if (req.body && Object.keys(req.body).length > 0) {
                    console.log(`[${timestamp}] [REQUEST_${requestId}] Body:`, JSON.stringify(req.body, null, 2));
                }
                console.log(`[${timestamp}] [REQUEST_${requestId}] Query:`, JSON.stringify(req.query, null, 2));

                // Store request data
                this.debugRequests.set(requestId, { request: requestData });

                // Cleanup old entries if we exceed the limit
                if (this.debugRequests.size > this.maxDebugEntries) {
                    const oldestKey = this.debugRequests.keys().next().value;
                    this.debugRequests.delete(oldestKey);
                }

                // Store request ID for response logging
                req.requestId = requestId;
                req.startTime = startTime;

                // Override res.json to log responses
                const originalJson = res.json;
                const self = this;
                res.json = function (body) {
                    const responseTime = Date.now() - req.startTime;
                    const responseTimestamp = new Date().toISOString();

                    // Store response data
                    const debugEntry = self.debugRequests.get(requestId);
                    if (debugEntry) {
                        debugEntry.response = {
                            timestamp: responseTimestamp,
                            responseTime: responseTime,
                            status: res.statusCode,
                            headers: { ...res.getHeaders() },
                            body: body ? JSON.parse(JSON.stringify(body)) : null,
                            type: 'json'
                        };
                    }

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

                    // Store response data
                    const debugEntry = self.debugRequests.get(requestId);
                    if (debugEntry) {
                        debugEntry.response = {
                            timestamp: responseTimestamp,
                            responseTime: responseTime,
                            status: res.statusCode,
                            headers: { ...res.getHeaders() },
                            body: body,
                            type: 'text'
                        };
                    }

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
                    const responseTime = Date.now() - req.startTime;
                    const responseTimestamp = new Date().toISOString();

                    // Store response data for any response that goes through res.end
                    const debugEntry = self.debugRequests.get(requestId);
                    if (debugEntry && !debugEntry.response) {
                        debugEntry.response = {
                            timestamp: responseTimestamp,
                            responseTime: responseTime,
                            status: res.statusCode,
                            headers: { ...res.getHeaders() },
                            body: chunk || null,
                            type: chunk ? 'raw' : 'empty'
                        };
                    }

                    if (chunk) {
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ========== OUTGOING RESPONSE ==========`);
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Status: ${res.statusCode}`);
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Response Time: ${responseTime}ms`);
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Headers:`, JSON.stringify(res.getHeaders(), null, 2));
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Chunk: ${chunk}`);
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ================================================`);
                    }

                    return originalEnd.call(this, chunk, encoding);
                };

                // Add a finish event listener as a fallback to capture all responses
                res.on('finish', () => {
                    const debugEntry = self.debugRequests.get(requestId);
                    if (debugEntry && !debugEntry.response) {
                        const responseTime = Date.now() - req.startTime;
                        const responseTimestamp = new Date().toISOString();

                        debugEntry.response = {
                            timestamp: responseTimestamp,
                            responseTime: responseTime,
                            status: res.statusCode,
                            headers: { ...res.getHeaders() },
                            body: null,
                            type: 'finish'
                        };

                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ========== OUTGOING RESPONSE (FINISH) ==========`);
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Status: ${res.statusCode}`);
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Response Time: ${responseTime}ms`);
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] Headers:`, JSON.stringify(res.getHeaders(), null, 2));
                        console.log(`[${responseTimestamp}] [RESPONSE_${requestId}] ================================================`);
                    }
                });

                next();
            });
        }


        this.app.use(express.urlencoded({ extended: true }));
        
        // Add multer middleware for multipart/form-data
        const upload = multer();
        this.app.use(upload.none()); // For forms without file uploads

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
        this.app.use('/static', express.static('static'));
        this.app.use('/templates', express.static('templates'));
    }

    async initializeServices() {

        console.log('📋 Creating services...');
        console.log('Application path: ', this.appPath);

        this.services.dashboard = new DashboardService(this.appPath);
        this.services.launcherProxy = new LauncherProxyService(this.appPath);
        this.services.unifiedOAuth = new UnifiedOAuthService(this.appPath);

        try {
            // Initialize Dashboard Service (already created)
            console.log('  📊 Initializing Dashboard Service...');
            await this.services.dashboard.initialize();
            console.log('  ✅ Dashboard Service ready');

            // Initialize Launcher Proxy Service (already created)
            console.log('  🚀 Initializing Launcher Proxy Service...');
            await this.services.launcherProxy.initialize();
            console.log('  ✅ Launcher Proxy Service ready');

            // Initialize Unified OAuth Service
            console.log('  🔐 Initializing Unified OAuth Service...');
            await this.services.unifiedOAuth.initialize();
            console.log('  ✅ Unified OAuth Service ready');

            console.log('✅ All services initialized successfully');
        } catch (error) {
            console.error('❌ Error initializing services:', error);
            throw error;
        }
    }

    async setupServiceRoutes() {
        // Debug endpoint - show request/response history (keeping here for access to debug data)
        this.app.get('/debug', (req, res) => {
            const { method, url, status, limit } = req.query;
            let debugData = Array.from(this.debugRequests.values());

            // Filter by method
            if (method) {
                debugData = debugData.filter(entry =>
                    entry.request.method.toLowerCase() === method.toLowerCase()
                );
            }

            // Filter by URL
            if (url) {
                debugData = debugData.filter(entry =>
                    entry.request.url.includes(url)
                );
            }

            // Filter by status
            if (status) {
                debugData = debugData.filter(entry =>
                    entry.response && entry.response.status.toString() === status
                );
            }

            // Sort by request time (ascending by default)
            debugData.sort((a, b) => a.request.startTime - b.request.startTime);

            // Limit results
            const limitNum = parseInt(limit) || 100;
            debugData = debugData.slice(-limitNum);

            const html = this.generateDebugHtml(debugData);
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
        });

        // Dashboard routes (prefix: /dashboard)
        this.app.use('/dashboard', this.services.dashboard.getRouter());

        // Unified OAuth Service routes - single consolidated router
        this.app.use('/oauth', this.services.unifiedOAuth.getRouter());
        this.app.use('/', this.services.unifiedOAuth.getRouter()); // For root-level endpoints (/authorize, /.well-known/*)

        // Apply OpenID Connect middleware to /mcp/* routes
        const oidcMiddleware = this.services.unifiedOAuth.getOpenIDConnectMiddleware();
        this.app.use('/mcp', oidcMiddleware);

        // Launcher Proxy routes - Mount under /mcp to match OAuth discovery document
        this.app.use("/mcp", this.services.launcherProxy.getRouter());

        // Fallback route
        this.app.use('*', (req, res) => {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                error: 'Route not found',
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
