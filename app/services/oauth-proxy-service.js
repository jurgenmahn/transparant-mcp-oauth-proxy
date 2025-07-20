import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import bcrypt from 'bcrypt';
import { URL } from 'url';
import { request } from 'undici';
import dns from 'dns';
import YAML from 'yaml';

const dnsPromises = dns.promises;

export class OAuthProxyService {
    constructor() {
        this.router = express.Router();
        this.loginRouter = express.Router();
        this.consentRouter = express.Router();
        this.config = {};
        
        this.setupMiddleware();
        this.setupRoutes();
    }
    
    async initialize() {
        await this.loadConfig();
        console.log('OAuth Proxy Service initialized');
    }
    
    async loadConfig() {
        try {
            this.config = YAML.parse(fs.readFileSync('./config/local.yaml', 'utf-8'));
        } catch (error) {
            console.error('Error loading OAuth proxy config:', error);
            throw error;
        }
    }
    
    setupMiddleware() {
        this.router.use(bodyParser.urlencoded({ extended: false }));
        this.loginRouter.use(bodyParser.urlencoded({ extended: false }));
        this.consentRouter.use(bodyParser.urlencoded({ extended: false }));
    }
    
    // Template loading and rendering utilities
    loadTemplate(templateName) {
        return fs.readFileSync(`./templates/${templateName}.html`, 'utf-8');
    }
    
    renderTemplate(template, replacements) {
        return Object.entries(replacements).reduce(
            (html, [key, val]) => html.replace(new RegExp(`{{${key}}}`, 'g'), val),
            template
        );
    }
    
    // Helper function to get client from Hydra
    async getClient(client_id) {
        try {
            console.log('Calling Hydra at:', `${this.config.hydra.admin_url}/admin/clients/${client_id}`);
            const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/clients/${client_id}`, {
                headers: {
                    Host: this.config.hydra.hostname
                }
            });
            
            if (response.statusCode === 200) {
                const body = await response.body.json();
                console.log('Client data:', JSON.stringify(body, null, 2));
                return body;
            } else {
                console.error('Failed to get client:', response.statusCode);
                return null;
            }
        } catch (error) {
            console.error('Error getting client from Hydra:', error);
            return null;
        }
    }
    
    // Validate redirect URI
    async validateRedirectUri(redirect_uri, allowed_domains) {
        try {
            const url = new URL(redirect_uri);
            
            // Check if domain is in allowed list
            const isAllowed = allowed_domains.some(allowedDomain => {
                const allowedUrl = new URL(allowedDomain);
                return url.hostname === allowedUrl.hostname;
            });
            
            if (!isAllowed) {
                console.log(`Redirect URI domain ${url.hostname} not in allowed list`);
                return false;
            }
            
            // Additional DNS resolution check for security
            try {
                await dnsPromises.resolve(url.hostname);
                return true;
            } catch (dnsError) {
                console.log(`DNS resolution failed for ${url.hostname}`);
                return false;
            }
        } catch (error) {
            console.log(`Invalid redirect URI format: ${redirect_uri}`);
            return false;
        }
    }
    
    // Validate scopes
    validateScopes(requestedScopes, allowedScopes) {
        if (!requestedScopes) return true;
        
        const scopes = requestedScopes.split(' ');
        return scopes.every(scope => allowedScopes.includes(scope));
    }
    
    setupRoutes() {
        // OAuth authorization endpoint
        this.router.get('/oauth2/auth', async (req, res) => {
            try {
                console.log('OAuth2 auth request:', req.query);
                
                const { client_id, redirect_uri, scope, state, response_type, code_challenge, code_challenge_method } = req.query;
                
                // Validate required parameters
                if (!client_id || !redirect_uri || !response_type) {
                    return res.status(400).send('Missing required parameters');
                }
                
                // Validate redirect URI against allowed domains
                const isValidRedirectUri = await this.validateRedirectUri(redirect_uri, this.config.oauth.allowed_redirect_domains);
                if (!isValidRedirectUri) {
                    return res.status(400).send('Invalid redirect URI domain');
                }
                
                // Validate scopes
                const isValidScope = this.validateScopes(scope, this.config.oauth.allowed_scopes);
                if (!isValidScope) {
                    return res.status(400).send('Invalid scope requested');
                }
                
                // Get client information from Hydra
                const client = await this.getClient(client_id);
                if (!client) {
                    return res.status(400).send('Invalid client');
                }
                
                // Forward to Hydra with validation passed
                const hydraParams = new URLSearchParams(req.query);
                const hydraUrl = `${this.config.hydra.public_url}/oauth2/auth?${hydraParams.toString()}`;
                
                console.log('Redirecting to Hydra:', hydraUrl);
                res.redirect(hydraUrl);
                
            } catch (error) {
                console.error('Error in OAuth2 auth:', error);
                res.status(500).send('Internal server error');
            }
        });
        
        // Token endpoint proxy
        this.router.post('/oauth2/token', async (req, res) => {
            try {
                console.log('Token request:', req.body);
                
                // Forward to Hydra
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/oauth2/token`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': req.headers.authorization || ''
                    },
                    body: new URLSearchParams(req.body).toString()
                });
                
                const body = await response.body.text();
                res.status(response.statusCode).send(body);
                
            } catch (error) {
                console.error('Error in token endpoint:', error);
                res.status(500).json({ error: 'internal_server_error' });
            }
        });
        
        // Well-known endpoints
        this.router.get('/.well-known/openid-configuration', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/.well-known/openid-configuration`);
                const body = await response.body.text();
                res.status(response.statusCode).send(body);
            } catch (error) {
                console.error('Error in well-known endpoint:', error);
                res.status(500).send('Internal server error');
            }
        });
        
        // Userinfo endpoint
        this.router.get('/userinfo', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/userinfo`, {
                    headers: {
                        'Authorization': req.headers.authorization || ''
                    }
                });
                const body = await response.body.text();
                res.status(response.statusCode).send(body);
            } catch (error) {
                console.error('Error in userinfo endpoint:', error);
                res.status(500).send('Internal server error');
            }
        });
        
        // Revocation endpoint
        this.router.post('/oauth2/revoke', async (req, res) => {
            try {
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.public_port}/oauth2/revoke`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': req.headers.authorization || ''
                    },
                    body: new URLSearchParams(req.body).toString()
                });
                
                res.status(response.statusCode).send('');
            } catch (error) {
                console.error('Error in revoke endpoint:', error);
                res.status(500).send('Internal server error');
            }
        });
    }
    
    setupLoginRoutes() {
        // Login page
        this.loginRouter.get('/', async (req, res) => {
            try {
                const { login_challenge } = req.query;
                
                if (!login_challenge) {
                    return res.status(400).send('Missing login challenge');
                }
                
                // Get login request from Hydra
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/login?login_challenge=${login_challenge}`);
                
                if (response.statusCode !== 200) {
                    return res.status(400).send('Invalid login challenge');
                }
                
                const loginRequest = await response.body.json();
                console.log('Login request:', loginRequest);
                
                // Render login form
                const template = this.loadTemplate('login');
                const html = this.renderTemplate(template, {
                    login_challenge: login_challenge,
                    client_name: loginRequest.client?.client_name || 'Unknown Application',
                    requested_scope: loginRequest.requested_scope?.join(' ') || ''
                });
                
                res.send(html);
                
            } catch (error) {
                console.error('Error in login page:', error);
                res.status(500).send('Internal server error');
            }
        });
        
        // Login form submission
        this.loginRouter.post('/', async (req, res) => {
            try {
                const { email, password, login_challenge, remember } = req.body;
                
                if (!login_challenge) {
                    return res.status(400).send('Missing login challenge');
                }
                
                // Authenticate user
                const user = this.config.users.find(u => u.email === email);
                
                if (!user || !await bcrypt.compare(password, user.password_hash)) {
                    // Render login form with error
                    const template = this.loadTemplate('login');
                    const html = this.renderTemplate(template, {
                        login_challenge: login_challenge,
                        error: 'Invalid email or password',
                        client_name: 'Application',
                        requested_scope: ''
                    });
                    return res.send(html);
                }
                
                // Accept login request
                const acceptResponse = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/login/accept?login_challenge=${login_challenge}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        subject: user.email,
                        remember: remember === 'on',
                        remember_for: 3600
                    })
                });
                
                if (acceptResponse.statusCode !== 200) {
                    return res.status(500).send('Failed to accept login');
                }
                
                const acceptResult = await acceptResponse.body.json();
                res.redirect(acceptResult.redirect_to);
                
            } catch (error) {
                console.error('Error in login submission:', error);
                res.status(500).send('Internal server error');
            }
        });
    }
    
    setupConsentRoutes() {
        // Consent page
        this.consentRouter.get('/', async (req, res) => {
            try {
                const { consent_challenge } = req.query;
                
                if (!consent_challenge) {
                    return res.status(400).send('Missing consent challenge');
                }
                
                // Get consent request from Hydra
                const response = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/consent?consent_challenge=${consent_challenge}`);
                
                if (response.statusCode !== 200) {
                    return res.status(400).send('Invalid consent challenge');
                }
                
                const consentRequest = await response.body.json();
                console.log('Consent request:', consentRequest);
                
                // Render consent form
                const template = this.loadTemplate('consent');
                const html = this.renderTemplate(template, {
                    consent_challenge: consent_challenge,
                    client_name: consentRequest.client?.client_name || 'Unknown Application',
                    requested_scope: consentRequest.requested_scope?.join(', ') || '',
                    user: consentRequest.subject || 'Unknown User'
                });
                
                res.send(html);
                
            } catch (error) {
                console.error('Error in consent page:', error);
                res.status(500).send('Internal server error');
            }
        });
        
        // Consent form submission
        this.consentRouter.post('/', async (req, res) => {
            try {
                const { consent_challenge, grant_scope, remember } = req.body;
                
                if (!consent_challenge) {
                    return res.status(400).send('Missing consent challenge');
                }
                
                // Get consent request details
                const getResponse = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/consent?consent_challenge=${consent_challenge}`);
                const consentRequest = await getResponse.body.json();
                
                // Accept consent request
                const acceptResponse = await request(`http://${this.config.hydra.hostname}:${this.config.hydra.admin_port}/admin/oauth2/auth/requests/consent/accept?consent_challenge=${consent_challenge}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        grant_scope: Array.isArray(grant_scope) ? grant_scope : (grant_scope ? [grant_scope] : []),
                        remember: remember === 'on',
                        remember_for: 3600,
                        session: {
                            access_token: {
                                email: consentRequest.subject
                            },
                            id_token: {
                                email: consentRequest.subject
                            }
                        }
                    })
                });
                
                if (acceptResponse.statusCode !== 200) {
                    return res.status(500).send('Failed to accept consent');
                }
                
                const acceptResult = await acceptResponse.body.json();
                res.redirect(acceptResult.redirect_to);
                
            } catch (error) {
                console.error('Error in consent submission:', error);
                res.status(500).send('Internal server error');
            }
        });
    }
    
    getRouter() {
        return this.router;
    }
    
    getLoginRouter() {
        this.setupLoginRoutes();
        return this.loginRouter;
    }
    
    getConsentRouter() {
        this.setupConsentRoutes();
        return this.consentRouter;
    }
    
    async shutdown() {
        console.log('OAuth Proxy Service shutting down...');
        // No specific cleanup needed
    }
}