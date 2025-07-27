import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { URL } from 'url';
import { request } from 'undici';
import dns from 'dns';
import YAML from 'yaml';
import crypto from 'crypto';
import { createClient } from 'redis';

const dnsPromises = dns.promises;

export class UnifiedOAuthService {
    constructor(appPath) {
        this.appPath = appPath;
        this.router = express.Router();
        this.loginRouter = express.Router();
        this.consentRouter = express.Router();
        this.config = {};
        this.redisClient = null;
        this.sessions = new Map(); // Fallback in-memory session store

        // Load config
        try {
            this.config = YAML.parse(fs.readFileSync(this.appPath + '/config/local.yaml', 'utf-8'));

            // Validate required config exists
            if (!this.config.oauth) {
                throw new Error('OAuth configuration missing from local.yaml');
            }
            if (!this.config.oauth.session_secret) {
                throw new Error('oauth.session_secret missing from local.yaml');
            }
            if (!this.config.cors) {
                throw new Error('cors configuration missing from local.yaml');
            }
            if (!this.config.cors.allowed_origins) {
                throw new Error('cors.allowed_origins missing from local.yaml');
            }
            if (!this.config.redis) {
                throw new Error('redis configuration missing from local.yaml');
            }
            if (!this.config.redis.host) {
                throw new Error('redis.host missing from local.yaml');
            }
            if (!this.config.redis.port) {
                throw new Error('redis.port missing from local.yaml');
            }

        } catch (error) {
            console.error('Warning: Could not load OAuth config:', error.message);
            throw new Error('Warning: Could not load OAuth config: ' + error.message);
        }

        // Normalize configured domains and scopes to avoid mismatches due to whitespace
        if (Array.isArray(this.config.oauth.allowed_redirect_domains)) {
            this.config.oauth.allowed_redirect_domains = this.config.oauth.allowed_redirect_domains.map(d => d.trim());
        }
        if (Array.isArray(this.config.oauth.allowed_scopes)) {
            this.config.oauth.allowed_scopes = this.config.oauth.allowed_scopes.map(s => s.trim());
        }
        if (this.config.cors && Array.isArray(this.config.cors.allowed_origins)) {
            this.config.cors.allowed_origins = this.config.cors.allowed_origins.map(o => o.trim());
        }

        this.setupMiddleware();
        this.setupRoutes();
    }

    async initialize() {
        console.log('Unified OAuth Service initializing...');
        await this.connectRedis();
        console.log('Unified OAuth Service initialized');
    }

    async connectRedis() {
        try {
            this.redisClient = createClient({
                socket: {
                    host: this.config.redis.host,
                    port: this.config.redis.port,
                    connectTimeout: 5000,
                    lazyConnect: true
                }
            });

            this.redisClient.on('error', (err) => {
                console.error('Redis Client Error:', err);
                this.redisClient = null; // Fallback to in-memory
            });

            this.redisClient.on('connect', () => {
                console.log('[REDIS] Connected successfully');
            });

            await this.redisClient.connect();
        } catch (error) {
            console.error('Redis connection failed, using in-memory store:', error);
            this.redisClient = null;
        }
    }

    // Session management with Redis fallback
    async setSession(sessionId, sessionData, ttlSeconds = 3600) {
        try {
            if (this.redisClient) {
                const sessionKey = `session:${sessionId}`;
                await this.redisClient.setEx(sessionKey, ttlSeconds, JSON.stringify(sessionData));
                console.log(`[REDIS] Session ${sessionId} stored with TTL ${ttlSeconds}s`);
            } else {
                // Fallback to in-memory
                this.sessions.set(sessionId, {
                    ...sessionData,
                    expires: Date.now() + (ttlSeconds * 1000)
                });
                console.log(`[MEMORY] Session ${sessionId} stored with TTL ${ttlSeconds}s`);
            }
        } catch (error) {
            console.error('Error setting session:', error);
            // Fallback to in-memory on Redis error
            this.sessions.set(sessionId, {
                ...sessionData,
                expires: Date.now() + (ttlSeconds * 1000)
            });
        }
    }

    async getSession(sessionId) {
        try {
            if (this.redisClient) {
                const sessionKey = `session:${sessionId}`;
                const sessionData = await this.redisClient.get(sessionKey);
                if (sessionData) {
                    console.log(`[REDIS] Session ${sessionId} retrieved`);
                    return JSON.parse(sessionData);
                }
                return null;
            } else {
                // Fallback to in-memory
                const session = this.sessions.get(sessionId);
                if (session && session.expires > Date.now()) {
                    console.log(`[MEMORY] Session ${sessionId} retrieved`);
                    return session;
                } else if (session) {
                    this.sessions.delete(sessionId); // Clean up expired session
                    console.log(`[MEMORY] Session ${sessionId} expired and removed`);
                }
                return null;
            }
        } catch (error) {
            console.error('Error getting session:', error);
            // Fallback to in-memory on Redis error
            const session = this.sessions.get(sessionId);
            return (session && session.expires > Date.now()) ? session : null;
        }
    }

    async deleteSession(sessionId) {
        try {
            if (this.redisClient) {
                const sessionKey = `session:${sessionId}`;
                await this.redisClient.del(sessionKey);
                console.log(`[REDIS] Session ${sessionId} deleted`);
            } else {
                // Fallback to in-memory
                this.sessions.delete(sessionId);
                console.log(`[MEMORY] Session ${sessionId} deleted`);
            }
        } catch (error) {
            console.error('Error deleting session:', error);
            // Fallback to in-memory on Redis error
            this.sessions.delete(sessionId);
        }
    }

    setupMiddleware() {
        this.router.use(bodyParser.urlencoded({ extended: false }));
        this.loginRouter.use(bodyParser.urlencoded({ extended: false }));
        this.consentRouter.use(bodyParser.urlencoded({ extended: false }));

        // Enhanced CORS middleware (replacing APISIX CORS)
        this.router.use((req, res, next) => {
            const origin = req.headers.origin;
            const allowedOrigins = this.config.cors?.allowed_origins || [];

            if (allowedOrigins.includes(origin)) {
                res.setHeader('Access-Control-Allow-Origin', origin);
            }

            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Access-Token, X-ID-Token, X-Userinfo, Mcp-Session-Id');
            res.setHeader('Access-Control-Allow-Credentials', 'true');

            if (req.method === 'OPTIONS') {
                return res.sendStatus(200);
            }
            next();
        });

        // Static file serving (replacing nginx on port 9280)
        this.router.use('/static', express.static(`${this.appPath}/../static`));
        this.router.use('/static', express.static('templates'));
        this.router.use('/static', express.static('public'));
        this.router.use(express.static('public'));

        // Parse cookies for session management
        this.router.use((req, res, next) => {
            req.cookies = {};
            if (req.headers.cookie) {
                req.headers.cookie.split(';').forEach(cookie => {
                    const [name, value] = cookie.trim().split('=');
                    req.cookies[name] = decodeURIComponent(value);
                });
            }
            next();
        });
    }

    // Template loading and rendering utilities
    loadTemplate(templateName) {
        try {
            const templatePath = `${this.appPath}/templates/${templateName}`;
            return fs.readFileSync(templatePath, 'utf-8');
        } catch (error) {
            console.error(`Error loading template ${templateName}:`, error);
            return null;
        }
    }

    renderTemplate(templateName, variables = {}) {
        let template = this.loadTemplate(templateName);
        if (!template) {
            return '<html><body><h1>Template not found</h1></body></html>';
        }

        // Replace variables in template
        for (const [key, value] of Object.entries(variables)) {
            template = template.replace(new RegExp(`{{${key}}}`, 'g'), value);
        }

        return template;
    }

    // Validation utilities
    async validateRedirectUri(redirectUri, allowedDomains) {
        if (!redirectUri) return false;

        try {
            const url = new URL(redirectUri);
            const hostname = url.hostname;

            // Allow exact domain matches or subdomain matches
            return allowedDomains.some(domain => {
                return hostname === domain || hostname.endsWith('.' + domain);
            });
        } catch (error) {
            console.error('Invalid redirect URI format:', error);
            return false;
        }
    }

    validateScopes(requestedScopes, allowedScopes) {
        if (!requestedScopes) return false;

        const scopes = requestedScopes.split(/\s+/);
        return scopes.every(scope => allowedScopes.includes(scope));
    }

    // OAuth2 Authorization endpoint handler
    handleOAuth2Auth = async (req, res) => {
        const {
            response_type,
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            code_challenge_method
        } = req.query;

        console.log(`[OAUTH] Authorization request: client_id=${client_id}, redirect_uri=${redirect_uri}, scope=${scope}`);

        // Basic parameter validation
        if (!response_type || !client_id || !redirect_uri) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            return res.end('Missing required parameters');
        }

        if (response_type !== 'code') {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            return res.end('Unsupported response_type');
        }

        // Validate redirect URI
        const isValidRedirectUri = await this.validateRedirectUri(redirect_uri, this.config.oauth.allowed_redirect_domains);
        if (!isValidRedirectUri) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            return res.end('Invalid redirect URI domain');
        }

        // Validate scopes
        const isValidScope = this.validateScopes(scope, this.config.oauth.allowed_scopes);
        if (!isValidScope) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            return res.end('Invalid scope requested: ' + scope);
        }

        // Client must already be registered via /oauth/register endpoint
        // Auth endpoint only handles authorization flow (login/consent)

        // Store state if provided (for CSRF protection)
        if (state) {
            await this.setSession(`state:${state}`, {
                originalUrl: req.originalUrl,
                redirect_uri: redirect_uri, // Store original redirect_uri for token exchange
                timestamp: Date.now()
            }, 300); // 5 minute TTL for state
        }

        // Forward to Hydra with proper proxy handling
        const hydraParams = new URLSearchParams(req.query);
        const hydraUrl = `http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/oauth2/auth?${hydraParams.toString()}`;

        try {
            console.log(`[OAUTH] Forwarding to Hydra: ${hydraUrl}`);
            const hydraResponse = await request(hydraUrl, {
                method: req.method,
                headers: {
                    ...req.headers,
                    'host': `${this.config.hydra.hostname}:${this.config.hydra.public_port}`
                }
            });

            // Handle Hydra response
            if (hydraResponse.statusCode >= 300 && hydraResponse.statusCode < 400) {
                // Hydra is redirecting - follow the redirect
                const location = hydraResponse.headers.location;
                console.log(`[OAUTH] Hydra redirect to: ${location}`);

                // Replace internal URLs with external ones
                let externalLocation = location;
                if (location.includes(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}`)) {
                    externalLocation = location.replace(
                        `http://${this.config.hydra.hostname}:${this.config.hydra.public_port}`,
                        this.config.hydra.public_url
                    );
                }

                // Forward all headers including Set-Cookie for CSRF tokens
                const responseHeaders = {
                    'Location': externalLocation,
                    'Content-Type': hydraResponse.headers['content-type'] || 'text/html'
                };

                // Forward Set-Cookie headers to maintain CSRF tokens
                if (hydraResponse.headers['set-cookie']) {
                    responseHeaders['Set-Cookie'] = hydraResponse.headers['set-cookie'];
                    console.log(`[OAUTH] Forwarding cookies:`, hydraResponse.headers['set-cookie']);
                }

                res.writeHead(hydraResponse.statusCode, responseHeaders);
                return res.end();
            }

            // Forward response body for non-redirect responses
            const body = await hydraResponse.body.text();
            res.writeHead(hydraResponse.statusCode, {
                'Content-Type': hydraResponse.headers['content-type'] || 'text/html'
            });
            res.end(body);

        } catch (error) {
            console.error('Error forwarding to Hydra:', error);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Internal server error');
        }
    };

    // OAuth2 Client Registration endpoint handler
    handleOAuth2Register = async (req, res) => {
        const {
            client_id,
            client_name,
            client_secret,
            redirect_uris,
            scope,
            grant_types,
            response_types,
            token_endpoint_auth_method
        } = req.body;

        console.log(`[OAUTH] Client registration request: client_name=${client_name}`);

        // Basic parameter validation - only redirect_uris is required for dynamic registration
        if (!redirect_uris || !Array.isArray(redirect_uris) && typeof redirect_uris !== 'string') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Missing required parameter: redirect_uris' }));
        }

        // Generate client_id and client_secret if not provided (dynamic registration)
        const generatedClientId = client_id || `client_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
        const generatedClientSecret = client_secret || crypto.randomBytes(32).toString('base64');

        // Validate redirect URIs
        const redirectUriArray = Array.isArray(redirect_uris) ? redirect_uris : [redirect_uris];
        for (const redirectUri of redirectUriArray) {
            const isValidRedirectUri = await this.validateRedirectUri(redirectUri, this.config.oauth.allowed_redirect_domains);
            if (!isValidRedirectUri) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: `Invalid redirect URI domain: ${redirectUri}` }));
            }
        }

        // Validate scopes
        const clientScope = scope || 'openid';
        const isValidScope = this.validateScopes(clientScope, this.config.oauth.allowed_scopes);
        if (!isValidScope) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: `Invalid scope requested: ${clientScope}` }));
        }

        const safeScope = clientScope
            .split(/\s+/)
            .filter(s => this.config.oauth.allowed_scopes.includes(s))
            .join(' ') || 'openid';

        const clientPayload = {
            client_id: generatedClientId,
            client_name: client_name || 'OAuth Client',
            client_secret: generatedClientSecret,
            redirect_uris: redirectUriArray,
            scope: safeScope,
            grant_types: grant_types || ['authorization_code', 'refresh_token'],
            response_types: response_types || ['code'],
            token_endpoint_auth_method: token_endpoint_auth_method || 'client_secret_post'
        };

        try {
            // For dynamic registration, always create a new client (don't check if exists)
            console.log('[OAUTH] Registering new client with payload:', { ...clientPayload, client_secret: '[REDACTED]' });

            // Use POST to create the client
            const registerResponse = await request(
                `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/clients`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Host': this.config.hydra.hostname },
                    body: JSON.stringify(clientPayload)
                }
            );

            const registerBody = await registerResponse.body.text();
            console.log(`[OAUTH] Registration response: ${registerResponse.statusCode} - ${registerBody}`);

            if (registerResponse.statusCode >= 200 && registerResponse.statusCode < 300) {
                console.log('Client created successfully:', generatedClientId);
                res.writeHead(201, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({
                    client_id: generatedClientId,
                    client_secret: generatedClientSecret,
                    client_name: clientPayload.client_name,
                    redirect_uris: redirectUriArray,
                    scope: safeScope,
                    grant_types: clientPayload.grant_types,
                    response_types: clientPayload.response_types,
                    token_endpoint_auth_method: clientPayload.token_endpoint_auth_method
                }));
            } else {
                console.error('Failed to create client:', registerResponse.statusCode, registerBody);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ error: 'Failed to register OAuth client', details: registerBody }));
            }

        } catch (regError) {
            console.error('Error creating client:', regError);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
                error: 'Error during client registration',
                details: regError.message,
                url: `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/clients`
            }));
        }
    };

    // Get client from Hydra
    async getClient(clientId) {
        try {
            const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/clients/${clientId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Host': this.config.hydra.hostname
                }
            });
            return response;
        } catch (error) {
            console.error('Error getting client:', error);
            return null;
        }
    }

    setupRoutes() {
        // OAuth2 Authorization endpoint
        this.router.get('/oauth2/auth', this.handleOAuth2Auth);
        this.router.get('/authorize', this.handleOAuth2Auth);  // APISIX compatibility

        // OAuth2 Client Registration endpoint
        this.router.post('/oauth/register', this.handleOAuth2Register);

        // OAuth2 Issuer endpoint - OpenID Connect Discovery
        this.router.get('/oauth', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/.well-known/openid-configuration`);
                const body = await response.body.text();
                res.writeHead(response.statusCode, { 'Content-Type': response.headers['content-type'] || 'application/json' });
                res.end(body);
            } catch (error) {
                console.error('Error in oauth issuer endpoint:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Failed to fetch OAuth issuer configuration' }));
            }
        });

        // OAuth2 Token endpoint - proxy to Hydra
        this.router.post('/oauth2/token', async (req, res) => {
            try {
                // Convert body to proper format for undici
                let bodyData;
                if (req.headers['content-type']?.includes('application/x-www-form-urlencoded')) {
                    // Convert object to URL-encoded string
                    bodyData = new URLSearchParams(req.body).toString();
                } else {
                    // For other content types, stringify if needed
                    bodyData = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
                }

                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/oauth2/token`, {
                    method: 'POST',
                    headers: {
                        ...req.headers,
                        'host': `${this.config.hydra.hostname}:${this.config.hydra.public_port}`
                    },
                    body: bodyData
                });

                const body = await response.body.text();
                res.writeHead(response.statusCode, { 'Content-Type': response.headers['content-type'] || 'application/json' });
                res.end(body);
            } catch (error) {
                console.error('Error in token endpoint:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'internal_server_error' }));
            }
        });

        // OpenID Connect configuration endpoint - proxy to Hydra
        this.router.get('/.well-known/openid-configuration', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/.well-known/openid-configuration`);
                const body = await response.body.text();
                res.writeHead(response.statusCode, { 'Content-Type': response.headers['content-type'] || 'application/json' });
                res.end(body);
            } catch (error) {
                console.error('Error in well-known endpoint:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Failed to fetch OpenID configuration' }));
            }
        });

        // JWKS endpoint - proxy to Hydra
        this.router.get('/.well-known/jwks.json', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/.well-known/jwks.json`);
                const body = await response.body.text();
                res.writeHead(response.statusCode, { 'Content-Type': response.headers['content-type'] || 'application/json' });
                res.end(body);
            } catch (error) {
                console.error('Error in jwks endpoint:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Failed to fetch JWKS' }));
            }
        });

        // UserInfo endpoint - proxy to Hydra
        this.router.get('/userinfo', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/userinfo`, {
                    method: 'GET',
                    headers: {
                        ...req.headers,
                        'host': `${this.config.hydra.hostname}:${this.config.hydra.public_port}`
                    }
                });

                const body = await response.body.text();
                res.writeHead(response.statusCode, { 'Content-Type': response.headers['content-type'] || 'application/json' });
                res.end(body);
            } catch (error) {
                console.error('Error in userinfo endpoint:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'internal_server_error' }));
            }
        });

        // OAuth2 Token revocation endpoint - proxy to Hydra  
        this.router.post('/oauth2/revoke', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/oauth2/revoke`, {
                    method: 'POST',
                    headers: {
                        ...req.headers,
                        'host': `${this.config.hydra.hostname}:${this.config.hydra.public_port}`
                    },
                    body: req.body
                });

                const body = await response.body.text();
                res.writeHead(response.statusCode, { 'Content-Type': response.headers['content-type'] || 'application/json' });
                res.end(body);
            } catch (error) {
                console.error('Error in revoke endpoint:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'internal_server_error' }));
            }
        });

        // OAuth2 Token introspection endpoint - proxy to Hydra
        this.router.post('/oauth2/introspect', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/introspect`, {
                    method: 'POST',
                    headers: {
                        ...req.headers,
                        'host': `${this.config.hydra.hostname}:${this.config.hydra.admin_port}`
                    },
                    body: req.body
                });

                const body = await response.body.text();
                res.writeHead(response.statusCode, { 'Content-Type': response.headers['content-type'] || 'application/json' });
                res.end(body);
            } catch (error) {
                console.error('Error in introspect endpoint:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'internal_server_error' }));
            }
        });

        // OAuth callback handler - DISABLED for dynamic client registration
        // Each client must handle their own callback URLs
        this.router.get('/oauth/callback', async (req, res) => {
            res.status(400).json({ 
                error: 'Generic callback disabled', 
                message: 'Clients must use their own callback URLs registered during dynamic registration' 
            });
        });

        // Logout endpoint
        this.router.post('/logout', async (req, res) => {
            try {
                const sessionId = req.cookies['mcp-session'] || req.headers['mcp-session-id'];
                if (sessionId) {
                    await this.deleteSession(sessionId);
                }

                res.clearCookie('mcp-session');
                res.json({ success: true, message: 'Logged out successfully' });
            } catch (error) {
                console.error('Logout error:', error);
                res.status(500).json({ error: 'Logout failed' });
            }
        });

        // OAuth authorization server discovery - generate document directly
        this.router.get('/.well-known/oauth-authorization-server', (req, res) => {
            const discoveryDoc = this.generateOAuthAuthorizationServerDiscovery();
            res.setHeader('Content-Type', 'application/json');
            res.json(discoveryDoc);
        });

        // OAuth authorization server discovery with /mcp path
        this.router.get('/.well-known/oauth-authorization-server/mcp', (req, res) => {
            const discoveryDoc = this.generateOAuthAuthorizationServerDiscovery();
            res.setHeader('Content-Type', 'application/json');
            res.json(discoveryDoc);
        });

        // API docs route - Dynamic generation
        this.router.get('/docs', (req, res) => {
            const apiDocs = this.generateApiDocumentation();
            res.setHeader('Content-Type', 'text/html');
            res.send(apiDocs);
        });

        // Legacy route for backward compatibility
        this.router.get('/oauth/api-docs.html', (req, res) => {
            const apiDocs = this.generateApiDocumentation();
            res.setHeader('Content-Type', 'text/html');
            res.send(apiDocs);
        });

        // OAuth protected resource discovery - Dynamic generation
        this.router.get('/.well-known/oauth-protected-resource', (req, res) => {
            const discoveryDoc = this.generateOAuthProtectedResourceDiscovery();
            res.setHeader('Content-Type', 'application/json');
            res.json(discoveryDoc);
        });

        this.router.get('/.well-known/oauth-protected-resource/mcp', (req, res) => {
            const mcpDoc = this.generateOAuthProtectedResourceMcp();
            res.setHeader('Content-Type', 'application/json');
            res.json(mcpDoc);
        });

        this.router.get('/.well-known/oauth-protected-resource/mcp/*', (req, res) => {
            const mcpDoc = this.generateOAuthProtectedResourceMcp();
            res.setHeader('Content-Type', 'application/json');
            res.json(mcpDoc);
        });

        // Legacy routes for backward compatibility
        this.router.get('/oauth/oauth-protected-resource-discovery.json', (req, res) => {
            const discoveryDoc = this.generateOAuthProtectedResourceDiscovery();
            res.setHeader('Content-Type', 'application/json');
            res.json(discoveryDoc);
        });

        this.router.get('/oauth/oauth-protected-resource-mcp.json', (req, res) => {
            const mcpDoc = this.generateOAuthProtectedResourceMcp();
            res.setHeader('Content-Type', 'application/json');
            res.json(mcpDoc);
        });

        this.setupLoginRoutes();
        this.setupConsentRoutes();
    }

    // Exchange authorization code for tokens
    async exchangeCodeForTokens(code, originalRedirectUri = null, clientId = null, clientSecret = null) {
        try {
            // Use original redirect_uri if provided, otherwise default to our callback
            const redirectUri = originalRedirectUri || `${this.config.hydra?.public_url || 'http://localhost:3000'}/oauth/callback`;
            console.log(`[OIDC] Token exchange - redirect_uri: ${redirectUri}`);

            if (!clientId || !clientSecret) {
                throw new Error('Client credentials required for token exchange');
            }

            const tokenUrl = `http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/oauth2/token`;
            const tokenPayload = {
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: redirectUri,
                client_id: clientId,
                client_secret: clientSecret
            };

            console.log(`[OIDC] Token exchange request to: ${tokenUrl}`);
            console.log(`[OIDC] Token exchange payload:`, {
                ...tokenPayload,
                client_secret: '[REDACTED]'
            });

            // Use client_secret_post method: send client credentials in body per Hydra client registration
            const response = await request(tokenUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams(tokenPayload).toString()
            });

            if (response.statusCode === 200) {
                const tokenData = await response.body.json();
                console.log(`[OIDC] Token exchange successful`);
                return tokenData;
            }

            const errorBody = await response.body.text();
            console.error(`[OIDC] Token exchange failed: ${response.statusCode} - ${errorBody}`);
            console.error(`[OIDC] Request details:`, {
                url: tokenUrl,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic [REDACTED]'
                },
                body: new URLSearchParams(tokenPayload).toString()
            });
            return null;
        } catch (error) {
            console.error('Token exchange error:', error);
            return null;
        }
    }

    // Get user info from access token
    async getUserInfo(accessToken) {
        try {
            const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/userinfo`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.statusCode === 200) {
                return await response.body.json();
            }

            return null;
        } catch (error) {
            console.error('UserInfo error:', error);
            return null;
        }
    }

    // Generate OAuth Authorization Server Discovery document dynamically
    generateOAuthAuthorizationServerDiscovery() {
        const baseUrl = this.config.hydra?.public_url || `http://localhost:${this.config.server_port || 3000}`;

        return {
            "issuer": `${baseUrl}/oauth`,
            "authorization_endpoint": `${baseUrl}/oauth/oauth2/auth`,
            "token_endpoint": `${baseUrl}/oauth/oauth2/token`,
            "userinfo_endpoint": `${baseUrl}/oauth/userinfo`,
            "jwks_uri": `${baseUrl}/oauth/.well-known/jwks.json`,
            "registration_endpoint": `${baseUrl}/oauth/register`,
            "revocation_endpoint": `${baseUrl}/oauth/oauth2/revoke`,
            "introspection_endpoint": `${baseUrl}/oauth/oauth2/introspect`,
            "response_types_supported": ["code", "id_token", "token", "code id_token", "code token", "id_token token", "code id_token token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": this.config.oauth.allowed_scopes,
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
            "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "client_credentials"],
            "response_modes_supported": ["query", "fragment", "form_post"]
        };
    }

    // Generate OAuth Protected Resource Discovery document dynamically
    generateOAuthProtectedResourceDiscovery() {
        const baseUrl = this.config.hydra?.public_url || `http://localhost:${this.config.server_port || 3000}`;

        return {
            "issuer": `${baseUrl}/oauth`,
            "authorization_endpoint": `${baseUrl}/oauth/oauth2/auth`,
            "token_endpoint": `${baseUrl}/oauth/oauth2/token`,
            "userinfo_endpoint": `${baseUrl}/oauth/userinfo`,
            "revocation_endpoint": `${baseUrl}/oauth/oauth2/revoke`,
            "protected_resources": [
                {
                    "resource": `${baseUrl}/mcp`,
                    "scopes": ["mcp:read"],
                    "scopes_required": ["mcp:read"]
                }
            ]
        };
    }

    // Generate OAuth Protected Resource MCP document dynamically
    generateOAuthProtectedResourceMcp() {
        const baseUrl = this.config.hydra?.public_url || `http://localhost:${this.config.server_port || 3000}`;

        return {
            "resource": `${baseUrl}/mcp`,
            "scopes": ["mcp:read"],
            "scopes_required": ["mcp:read"],
            "authorization_endpoint": `${baseUrl}/oauth/oauth2/auth`,
            "token_endpoint": `${baseUrl}/oauth/oauth2/token`
        };
    }

    // Generate API documentation dynamically
    generateApiDocumentation() {
        const baseUrl = this.config.hydra?.public_url || `http://localhost:${this.config.server_port || 3000}`;

        const templateVars = {
            BASE_URL: baseUrl,
            CLIENT_ID: "Dynamic generated",
            SCOPES: this.config.oauth.allowed_scopes.join(" "),
        };

        return this.renderTemplate('api-docs.html', templateVars);
    }

    // Login routes setup
    setupLoginRoutes() {
        this.loginRouter.get('/', async (req, res) => {
            const { login_challenge } = req.query;

            if (!login_challenge) {
                return res.status(400).send('Missing login_challenge parameter');
            }

            try {
                // Get login request from Hydra
                const loginReq = await request(
                    `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/login?login_challenge=${login_challenge}`
                );

                if (loginReq.statusCode !== 200) {
                    return res.status(400).send('Invalid login challenge');
                }

                const loginInfo = await loginReq.body.json();

                const loginForm = this.renderTemplate('login.html', {
                    LOGIN_CHALLENGE: login_challenge,
                    CLIENT_NAME: loginInfo.client?.client_name || loginInfo.client?.client_id || 'Unknown Client',
                    REQUESTED_SCOPES: (loginInfo.requested_scope || []).join(', '),
                    ERROR: ''
                });

                res.setHeader('Content-Type', 'text/html');
                res.send(loginForm);

            } catch (error) {
                console.error('Login error:', error);
                res.status(500).send('Login failed');
            }
        });

        this.loginRouter.post('/', async (req, res) => {
            const { email, password, remember } = req.body;

            const challenge = req.query.login_challenge;
            if (!challenge) return res.status(400).send('Missing login_challenge');

            try {
                // Validate user credentials
                const isValidUser = await this.validateUser(email, password);

                if (!isValidUser) {
                    const loginForm = this.renderTemplate('login.html', {
                        LOGIN_CHALLENGE: login_challenge,
                        ERROR: 'Invalid email or password'
                    });

                    res.setHeader('Content-Type', 'text/html');
                    return res.send(loginForm);
                }

                // Accept the login request
                const acceptResponse = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/login/accept?login_challenge=${challenge}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        subject: email,
                        remember: true,
                        remember_for: 3600
                    }),
                    maxRedirects: 0
                });

                if (acceptResponse.statusCode === 200) {
                    const acceptData = await acceptResponse.body.json();
                    res.redirect(acceptData.redirect_to);
                } else {
                    res.status(500).send('Login acceptance failed');
                }

            } catch (error) {
                console.error('Login processing error:', error);
                res.status(500).send('Login failed');
            }
        });
    }

    // Consent routes setup
    setupConsentRoutes() {
        this.consentRouter.get('/', async (req, res) => {
            const { consent_challenge } = req.query;

            if (!consent_challenge) {
                return res.status(400).send('Missing consent_challenge parameter');
            }

            try {
                // Get consent request from Hydra
                const consentReq = await request(
                    `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/consent?consent_challenge=${consent_challenge}`
                );

                if (consentReq.statusCode !== 200) {
                    return res.status(400).send('Invalid consent challenge');
                }

                const consentInfo = await consentReq.body.json();

                // For other clients, show consent form
                const requestedScopes = consentInfo.requested_scope || [];
                const scopeList = requestedScopes.map(scope => `<li>${scope}</li>`).join('');
                const scopeHiddenFields = requestedScopes.map(scope => 
                    `<input type="hidden" name="grant_scope" value="${scope}">`
                ).join('');
                
                const consentForm = this.renderTemplate('consent.html', {
                    CONSENT_CHALLENGE: consent_challenge,
                    CLIENT_NAME: consentInfo.client?.client_name || consentInfo.client?.client_id || 'Unknown Client',
                    SCOPE_LIST: scopeList,
                    SCOPE_HIDDEN_FIELDS: scopeHiddenFields,
                    USER_ID: consentInfo.subject
                });

                res.setHeader('Content-Type', 'text/html');
                res.send(consentForm);

            } catch (error) {
                console.error('Consent error:', error);
                res.status(500).send('Consent failed');
            }
        });

        this.consentRouter.post('/', async (req, res) => {
            const { grant_scope, remember } = req.body;

            const challenge = req.query.consent_challenge;
            if (!challenge) return res.status(400).send('Missing consent_challenge');            

            try {
                const grantedScopes = Array.isArray(grant_scope) ? grant_scope : [grant_scope].filter(Boolean);

                // Accept the consent request
                const acceptResponse = await request(
                    `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/consent/accept?consent_challenge=${challenge}`,
                    {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            grant_scope: grantedScopes,
                            remember: true,
                            remember_for: 3600
                        }),
                    maxRedirects: 0
                    }
                );

                if (acceptResponse.statusCode === 200) {
                    const acceptData = await acceptResponse.body.json();
                    res.redirect(acceptData.redirect_to);
                } else {
                    res.status(500).send('Consent acceptance failed');
                }

            } catch (error) {
                console.error('Consent processing error:', error);
                res.status(500).send('Consent failed');
            }
        });
    }

    // User validation
    async validateUser(email, password) {
        try {
            if (!this.config.users || !Array.isArray(this.config.users)) {
                return false;
            }

            const user = this.config.users.find(u => u.email === email);
            if (!user) {
                return false;
            }

            // Compare password with bcrypt hash
            return await bcrypt.compare(password, user.password_hash);
        } catch (error) {
            console.error('User validation error:', error);
            return false;
        }
    }

    // Token-based authentication middleware for dynamic clients
    createOpenIDConnectMiddleware() {
        return async (req, res, next) => {
            try {
                console.log(`[AUTH] Processing request: ${req.method} ${req.path}`);

                // Skip authentication for specific paths
                const skipPaths = ['/health', '/login', '/consent', '/oauth', '/.well-known'];
                if (skipPaths.some(path => req.path.startsWith(path))) {
                    return next();
                }

                // Check for Bearer token in Authorization header
                const authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return res.status(401).json({ 
                        error: 'unauthorized', 
                        message: 'Bearer token required. Use OAuth2 flow to obtain access token.' 
                    });
                }

                const accessToken = authHeader.substring(7); // Remove 'Bearer ' prefix

                // Validate token with Hydra introspection
                try {
                    const introspectResponse = await request(
                        `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/introspect`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: new URLSearchParams({ token: accessToken }).toString()
                        }
                    );

                    if (introspectResponse.statusCode !== 200) {
                        return res.status(401).json({ 
                            error: 'unauthorized', 
                            message: 'Invalid access token' 
                        });
                    }

                    const tokenInfo = await introspectResponse.body.json();
                    
                    if (!tokenInfo.active) {
                        return res.status(401).json({ 
                            error: 'unauthorized', 
                            message: 'Access token is not active' 
                        });
                    }

                    // Check if token has required MCP scope
                    const scopes = tokenInfo.scope ? tokenInfo.scope.split(' ') : [];
                    if (!scopes.includes('mcp:read')) {
                        return res.status(403).json({ 
                            error: 'forbidden', 
                            message: 'Token missing required mcp:read scope' 
                        });
                    }

                    // Add user info to request
                    req.user = { 
                        sub: tokenInfo.sub,
                        client_id: tokenInfo.client_id,
                        scopes: scopes
                    };
                    req.accessToken = accessToken;

                    console.log(`[AUTH] Authenticated user: ${tokenInfo.sub} via client: ${tokenInfo.client_id}`);
                    return next();

                } catch (introspectError) {
                    console.error('Token introspection error:', introspectError);
                    return res.status(401).json({ 
                        error: 'unauthorized', 
                        message: 'Token validation failed' 
                    });
                }

            } catch (error) {
                console.error('Auth Middleware error:', error);
                res.status(500).json({ error: 'Authentication failed' });
            }
        };
    }

    getRouter() {
        return this.router;
    }

    getLoginRouter() {
        return this.loginRouter;
    }

    getConsentRouter() {
        return this.consentRouter;
    }

    getOpenIDConnectMiddleware() {
        return this.createOpenIDConnectMiddleware();
    }

    async shutdown() {
        if (this.redisClient) {
            await this.redisClient.quit();
        }
    }
}
