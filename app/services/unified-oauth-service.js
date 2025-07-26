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
            if (!this.config.oauth.client_id) {
                throw new Error('oauth.client_id missing from local.yaml');
            }
            if (!this.config.oauth.client_secret) {
                throw new Error('oauth.client_secret missing from local.yaml');
            }
            if (!this.config.oauth.session_secret) {
                throw new Error('oauth.session_secret missing from local.yaml');
            }
            if (!this.config.oauth.scope) {
                throw new Error('oauth.scope missing from local.yaml');
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
            // Set default config for stub functionality
            this.config = {
                hydra: { hostname: '127.0.0.1', admin_port: 4445, public_port: 4444 },
                oauth: {
                    client_id: 'mcp-oauth-proxy',
                    allowed_redirect_domains: [],
                    allowed_scopes: ['openid', 'profile', 'email']
                },
                cors: { allowed_origins: [] },
                redis: { host: 'localhost', port: 6379 }
            };
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

        const safeScope = (scope || 'openid')
            .split(/\s+/)
            .filter(s => this.config.oauth.allowed_scopes.includes(s))
            .join(' ') || 'openid';

        const clientPayload = {
            client_id,
            client_name: 'MCP OAuth Proxy Client',
            client_secret: this.config.oauth.client_secret,
            redirect_uris: [redirect_uri],
            scope: safeScope,
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_post'
        };


        try {

            let data;
            await this.getClient(client_id).then(async (response) => {

                data = await response.body.text();
                console.log("Check if client already exist, response: ", data, " status code: ", response.statusCode);

                if (response.statusCode === 404) {

                    console.log('[OAUTH] Registering client with payload:', clientPayload);

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
                        console.log('Client created successfully:', client_id);
                    } else {
                        const errorBody = await registerResponse.body.text();
                        console.error('Failed to create client:', registerResponse.statusCode, errorBody);
                        res.writeHead(500, { 'Content-Type': 'text/plain' });
                        return res.end('Failed to configure OAuth client');
                    }

                } else if (response.statusCode >= 500) {
                    console.error('Hydra server error:', data);
                    return res.status(500).send('Hydra server error');
                }
            });

        } catch (regError) {
            console.error('Error creating/updating client:', regError);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            return res.end('Error during client configuration url: ' + `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/clients/${client_id}` + " payload: " + JSON.stringify(clientPayload));
        }

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

        // OAuth2 Token endpoint - proxy to Hydra
        this.router.post('/oauth2/token', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/oauth2/token`, {
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

        // OAuth callback handler (replaces APISIX flow)
        this.router.get('/oauth/callback', async (req, res) => {
            try {
                const { code, state, error } = req.query;

                if (error) {
                    return res.status(400).json({ error: 'OAuth error', details: error });
                }

                if (!code || !state) {
                    return res.status(400).json({ error: 'Missing code or state parameter' });
                }

                // Validate state
                const stateData = await this.getSession(`state:${state}`);
                if (!stateData) {
                    console.error(`[OIDC] Invalid state parameter: ${state}`);
                    return res.status(400).json({ error: 'Invalid state parameter' });
                }

                // Clean up state immediately to prevent reuse
                await this.deleteSession(`state:${state}`);

                // Debug log state data
                console.log(`[OIDC] State data:`, JSON.stringify(stateData, null, 2));
                console.log(`[OIDC] Using redirect_uri from state:`, stateData.redirect_uri);

                // Exchange code for tokens using original redirect_uri
                const tokenResponse = await this.exchangeCodeForTokens(code, stateData.redirect_uri);
                if (!tokenResponse) {
                    return res.status(500).json({ error: 'Failed to exchange code for tokens' });
                }

                // Get user info
                const userinfo = await this.getUserInfo(tokenResponse.access_token);

                // Create session
                const sessionId = crypto.randomBytes(32).toString('hex');
                const sessionTTL = tokenResponse.expires_in || 3600;
                await this.setSession(sessionId, {
                    user: { sub: userinfo?.sub || 'unknown' },
                    accessToken: tokenResponse.access_token,
                    idToken: tokenResponse.id_token,
                    refreshToken: tokenResponse.refresh_token,
                    userinfo: userinfo
                }, sessionTTL);

                // Set session cookie
                res.cookie('mcp-session', sessionId, {
                    httpOnly: true,
                    secure: req.secure,
                    maxAge: tokenResponse.expires_in * 1000
                });

                console.log(`[OIDC] OAuth callback successful, redirecting to: ${stateData.originalUrl}`);
                res.redirect(stateData.originalUrl || '/');

            } catch (error) {
                console.error('OAuth callback error:', error);
                res.status(500).json({ error: 'OAuth callback failed', details: error.message });
            }
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
    async exchangeCodeForTokens(code, originalRedirectUri = null) {
        try {
            // Use original redirect_uri if provided, otherwise default to our callback
            const redirectUri = originalRedirectUri || `${this.config.hydra?.public_url || 'http://localhost:3000'}/oauth/callback`;
            console.log(`[OIDC] Token exchange - redirect_uri: ${redirectUri}`);

            const tokenUrl = `http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/oauth2/token`;
            const tokenPayload = {
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: redirectUri,
                client_id: this.config.oauth.client_id,
                client_secret: this.config.oauth.client_secret
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
            "scopes_supported": ["openid", "profile", "email", "offline_access", "mcp:read"],
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
            CLIENT_ID: this.config.oauth.client_id,
            SCOPES: this.config.oauth.scope
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

                // Auto-approve for MCP client (no user interaction needed)
                if (loginInfo.client && loginInfo.client.client_id === 'mcp-oauth-proxy') {
                    console.log('[OAUTH-LOGIN] Auto-approving login for MCP client');

                    // Accept the login request
                    const acceptResponse = await request(
                        `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/login/accept?login_challenge=${login_challenge}`,
                        {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                subject: 'jurgen@mahn.it', // Auto-login as configured user
                                remember: true,
                                remember_for: 3600
                            })
                        }
                    );

                    if (acceptResponse.statusCode === 200) {
                        const acceptData = await acceptResponse.body.json();
                        return res.redirect(acceptData.redirect_to);
                    }
                }

                // For other clients, show login form
                const loginForm = this.renderTemplate('login.html', {
                    LOGIN_CHALLENGE: login_challenge,
                    CLIENT_NAME: loginInfo.client?.client_name || loginInfo.client?.client_id || 'Unknown Client',
                    REQUESTED_SCOPES: (loginInfo.requested_scope || []).join(', ')
                });

                res.setHeader('Content-Type', 'text/html');
                res.send(loginForm);

            } catch (error) {
                console.error('Login error:', error);
                res.status(500).send('Login failed');
            }
        });

        this.loginRouter.post('/', async (req, res) => {
            const { login_challenge, email, password, remember } = req.body;

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
                const acceptResponse = await request(
                    `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/login/accept?login_challenge=${login_challenge}`,
                    {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            subject: email,
                            remember: !!remember,
                            remember_for: remember ? 3600 : 0
                        })
                    }
                );

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

                // Auto-approve for MCP client (no user interaction needed)
                if (consentInfo.client && consentInfo.client.client_id === 'mcp-oauth-proxy') {
                    console.log('[OAUTH-CONSENT] Auto-approving consent for MCP client');

                    // Accept the consent request
                    const acceptResponse = await request(
                        `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/consent/accept?consent_challenge=${consent_challenge}`,
                        {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                grant_scope: consentInfo.requested_scope,
                                remember: true,
                                remember_for: 3600
                            })
                        }
                    );

                    if (acceptResponse.statusCode === 200) {
                        const acceptData = await acceptResponse.body.json();
                        return res.redirect(acceptData.redirect_to);
                    }
                }

                // For other clients, show consent form
                const consentForm = this.renderTemplate('consent.html', {
                    CONSENT_CHALLENGE: consent_challenge,
                    CLIENT_NAME: consentInfo.client?.client_name || consentInfo.client?.client_id || 'Unknown Client',
                    REQUESTED_SCOPES: (consentInfo.requested_scope || []).join(', '),
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
            const { consent_challenge, grant_scope, remember } = req.body;

            try {
                const grantedScopes = Array.isArray(grant_scope) ? grant_scope : [grant_scope].filter(Boolean);

                // Accept the consent request
                const acceptResponse = await request(
                    `http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/consent/accept?consent_challenge=${consent_challenge}`,
                    {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            grant_scope: grantedScopes,
                            remember: !!remember,
                            remember_for: remember ? 3600 : 0
                        })
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

    // OpenID Connect middleware (replacing APISIX openid-connect plugin)
    createOpenIDConnectMiddleware() {
        return async (req, res, next) => {
            try {
                console.log(`[OIDC] Processing request: ${req.method} ${req.path}`);

                // Skip authentication for specific paths
                const skipPaths = ['/health', '/login', '/consent', '/oauth', '/.well-known'];
                if (skipPaths.some(path => req.path.startsWith(path))) {
                    return next();
                }

                // Check for existing session
                const sessionId = req.cookies['mcp-session'] || req.headers['mcp-session-id'];
                if (sessionId) {
                    const session = await this.getSession(sessionId);

                    if (session) {
                        // Add user info to request
                        req.user = session.user;
                        req.accessToken = session.accessToken;
                        req.idToken = session.idToken;

                        // Set headers as APISIX did
                        res.setHeader('X-Access-Token', session.accessToken);
                        res.setHeader('X-ID-Token', session.idToken);
                        if (session.userinfo) {
                            res.setHeader('X-Userinfo', JSON.stringify(session.userinfo));
                        }

                        return next();
                    }
                }

                // No valid session - redirect to OAuth flow
                const state = crypto.randomBytes(16).toString('hex');
                const originalUrl = req.originalUrl;

                // Store original URL for redirect after auth
                await this.setSession(`state:${state}`, { originalUrl }, 300);

                const authUrl = new URL(`${this.config.hydra.public_url}/oauth/oauth2/auth`);
                authUrl.searchParams.set('response_type', 'code');
                authUrl.searchParams.set('client_id', this.config.oauth.client_id);
                authUrl.searchParams.set('redirect_uri', `${this.config.hydra.public_url}/oauth/callback`);
                authUrl.searchParams.set('scope', this.config.oauth.scope);
                authUrl.searchParams.set('state', state);

                console.log(`[OIDC] Redirecting to auth: ${authUrl.toString()}`);
                res.redirect(authUrl.toString());

            } catch (error) {
                console.error('OIDC Middleware error:', error);
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
