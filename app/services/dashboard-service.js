import express from 'express';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import yaml from 'yaml';
import session from 'express-session';
import { createClient as createRedisClient } from 'redis';
import { exec } from 'child_process';
import { promisify } from 'util';
import { request } from 'undici';

const execAsync = promisify(exec);

export class DashboardService {
    constructor(appPath, mcpServerRef = null) {
        this.appPath = appPath;
        this.mcpServerRef = mcpServerRef; // Access to server-level reloads
        this.router = express.Router();
        this.config = {};
        this.sessionStore = null;
        this.setupSession();
        this.setupRoutes();
        this.setupHashGenerationRoute();
        this.setupUserRoutes();
        this.setupRestartRoutes();
        this.setupStatsRoute();
        this.setupVersionRoute();
    }

    setupSession() {
        // Try to build a Redis-backed session store; fallback to MemoryStore
        const buildRedisStore = () => {
            const store = new (class RedisSessionStore extends session.Store {
                constructor(client, prefix = 'dash:sess:') {
                    super();
                    this.client = client;
                    this.prefix = prefix;
                }
                _key(sid) { return this.prefix + sid; }
                async get(sid, cb) {
                    try {
                        const v = await this.client.get(this._key(sid));
                        cb(null, v ? JSON.parse(v) : null);
                    } catch (e) { cb(e); }
                }
                async set(sid, sess, cb) {
                    try {
                        const maxAge = (sess?.cookie?.maxAge ?? sess?.cookie?.originalMaxAge);
                        const ttl = Math.max(60, Math.floor((maxAge ? maxAge : 24*60*60*1000) / 1000));
                        await this.client.setEx(this._key(sid), ttl, JSON.stringify(sess));
                        cb && cb(null);
                    } catch (e) { cb && cb(e); }
                }
                async destroy(sid, cb) {
                    try { await this.client.del(this._key(sid)); cb && cb(null); } catch (e) { cb && cb(e); }
                }
                async touch(sid, sess, cb) {
                    try {
                        const maxAge = (sess?.cookie?.maxAge ?? sess?.cookie?.originalMaxAge);
                        const ttl = Math.max(60, Math.floor((maxAge ? maxAge : 24*60*60*1000) / 1000));
                        await this.client.expire(this._key(sid), ttl);
                        cb && cb(null);
                    } catch (e) { cb && cb(e); }
                }
            })(this._initRedisClient());
            return store;
        };

        try {
            this.sessionStore = buildRedisStore();
        } catch {
            this.sessionStore = null;
        }

        const sessMiddleware = session({
            secret: process.env.SESSION_SECRET || 'mcp-dashboard-secret-change-in-production',
            resave: false,
            saveUninitialized: false,
            store: this.sessionStore || undefined,
            cookie: { secure: false, httpOnly: true, sameSite: 'lax' }
        });
        this.router.use(sessMiddleware);
    }

    _initRedisClient() {
        try {
            const cfgPath = path.resolve(this.appPath + '/config/local.yaml');
            // sync read for simplicity; setupSession runs at construction time
            let host = '127.0.0.1', port = 6379;
            try {
                const raw = fsSync.readFileSync(cfgPath, 'utf8');
                const cfg = yaml.parse(raw) || {};
                if (cfg.redis?.host) host = String(cfg.redis.host);
                if (cfg.redis?.port) port = Number(cfg.redis.port);
            } catch {}

            const client = createRedisClient({
                socket: { host, port, connectTimeout: 3000, keepAlive: 10000 }
            });
            client.on('error', (err) => console.error('[DASHBOARD] Redis error:', err?.message || err));
            client.connect().catch(err => console.error('[DASHBOARD] Redis connect failed:', err?.message || err));
            return client;
        } catch (e) {
            console.error('[DASHBOARD] Failed to create Redis client:', e?.message || e);
            return null;
        }
    }

    // Stats API
    setupStatsRoute() {
        this.router.get('/api/mcp-stats', this.requireAuth.bind(this), async (_req, res) => {
            try {
                // Load services from local.yaml (track enabled/disabled)
                const localPath = path.resolve(this.appPath + '/config/local.yaml');
                let configured = [];
                try {
                    const raw = await fs.readFile(localPath, 'utf8');
                    const cfg = yaml.parse(raw) || {};
                    const arr = Array.isArray(cfg.mcp_services) ? cfg.mcp_services : [];
                    configured = arr
                        .filter(s => s && s.name)
                        .map(s => ({ name: s.name, enabled: !(s.enabled === false || s.enabled === 'false') }));
                } catch {}

                // Load statistics file
                const statsPath = path.resolve(this.appPath + '/config/statistics.yaml');
                let stats = { services: {} };
                try {
                    const txt = await fs.readFile(statsPath, 'utf8');
                    stats = yaml.parse(txt) || { services: {} };
                } catch {}

                // Determine runtime status using launcher proxy if available
                let runningSet = new Set();
                try {
                    const lp = this.mcpServerRef?.services?.launcherProxy;
                    if (lp && lp.getServicesList) {
                        const runtime = lp.getServicesList(); // { name: { initialized, ... } }
                        runningSet = new Set(Object.keys(runtime || {}));
                    } else if (lp && lp.processes) {
                        runningSet = new Set([...lp.processes.keys()]);
                    }
                } catch {}

                const out = configured.map(svc => {
                    const rec = (stats.services && stats.services[svc.name]) || {};
                    let status = 'error';
                    if (!svc.enabled) status = 'disabled';
                    else if (runningSet.has(svc.name)) status = 'running';
                    return {
                        name: svc.name,
                        status,
                        calls: Number(rec.calls || 0),
                        bytes_in: Number(rec.bytes_in || 0),
                        bytes_out: Number(rec.bytes_out || 0),
                        last_call: rec.last_call || null
                    };
                });
                res.json({ services: out });
            } catch (e) {
                res.status(500).json({ error: 'Failed to load stats', detail: String(e?.message || e) });
            }
        });

        // Restart a single MCP service (reload latest config before restart)
        this.router.post('/api/mcp-service/restart', this.requireAuth.bind(this), async (req, res) => {
            try {
                const name = String(req.body?.name || '').trim();
                if (!name) return res.status(400).json({ error: 'Missing service name' });
                const lp = this.mcpServerRef?.services?.launcherProxy;
                if (!lp) return res.status(500).json({ error: 'Launcher proxy not available' });

                // Reload latest config and parsed services
                await lp.loadConfig();
                lp.services = await lp.parseServices(lp.config.mcp_services || []);

                // If not enabled in config, report disabled
                const defined = Array.isArray(lp.config.mcp_services) ? lp.config.mcp_services.find(s=>s?.name===name) : null;
                if (!defined) return res.status(404).json({ error: 'Service not configured' });
                const enabled = !(defined.enabled === false || defined.enabled === 'false');
                if (!enabled) return res.status(400).json({ error: 'Service is disabled in config' });

                const ok = await lp.restartService(name);
                if (!ok) return res.status(500).json({ error: 'Restart failed' });
                res.json({ success: true });
            } catch (e) {
                res.status(500).json({ error: 'Failed to restart service', detail: String(e?.message || e) });
            }
        });

        // List realtime available tools for a running MCP service
        this.router.get('/api/mcp-service/tools', this.requireAuth.bind(this), async (req, res) => {
            try {
                const name = String(req.query?.name || '').trim();
                if (!name) return res.status(400).json({ error: 'Missing service name' });
                const lp = this.mcpServerRef?.services?.launcherProxy;
                if (!lp) return res.status(500).json({ error: 'Launcher proxy not available' });
                const svc = lp.processes?.get ? lp.processes.get(name) : null;
                if (!svc || !svc.initialized) {
                    return res.json({ service: name, initialized: false, tools: [] });
                }
                const tools = Array.isArray(svc.tools) ? svc.tools.map(t => ({ name: t.name, description: t.description })) : [];
                res.json({ service: name, initialized: true, tools });
            } catch (e) {
                res.status(500).json({ error: 'Failed to list tools', detail: String(e?.message || e) });
            }
        });
    }

    async initialize() {
        await this.loadDashboardConfig();
        this.setupFullFileRoutes();
        console.log('Dashboard Service initialized');
    }

    async loadDashboardConfig() {
        const configPath = path.resolve(this.appPath + '/config/dashboard.yaml');
        const content = await fs.readFile(configPath, 'utf8');
        this.config = yaml.parse(content);
    }

    setupRoutes() {
        // Serve dashboard HTML as-is (hardcoded form rendered by client JS)
        this.router.get('/', async (_req, res) => {
            try {
                const templatePath = path.join(process.cwd(), 'templates', 'dashboard.html');
                const html = await fs.readFile(templatePath, 'utf8');
                res.send(html);
            } catch {
                res.status(500).send('Error loading configuration dashboard');
            }
        });

        // Authentication status
        this.router.get('/api/auth-status', (req, res) => {
            if (req.session?.authenticated) return res.json({ authenticated: true, email: req.session.userEmail });
            res.json({ authenticated: false });
        });

        // Logout
        this.router.post('/logout', (req, res) => { req.session.destroy(() => res.json({ success: true })); });

        // SSE server logs stream
        this.router.get('/api/server-logs', this.requireAuth.bind(this), (req, res) => {
            try {
                if (!this.mcpServerRef?.logEmitter) {
                    return res.status(500).json({ error: 'Log stream unavailable' });
                }
                res.setHeader('Content-Type', 'text/event-stream');
                res.setHeader('Cache-Control', 'no-cache');
                res.setHeader('Connection', 'keep-alive');
                res.flushHeaders?.();

                // Send recent buffer first
                const buf = Array.isArray(this.mcpServerRef.logBuffer) ? this.mcpServerRef.logBuffer : [];
                for (const rec of buf) {
                    res.write(`data: ${JSON.stringify(rec)}\n\n`);
                }

                const onLog = (rec) => {
                    try { res.write(`data: ${JSON.stringify(rec)}\n\n`); } catch {}
                };
                this.mcpServerRef.logEmitter.on('log', onLog);

                req.on('close', () => {
                    this.mcpServerRef.logEmitter.off('log', onLog);
                });
            } catch (e) {
                res.status(500).json({ error: 'Failed to open log stream' });
            }
        });

        // Admin: Flush full Redis DB/cache (FLUSHALL)
        this.router.post('/api/admin/redis-flush', this.requireAuth.bind(this), async (_req, res) => {
            try {
                const svc = this.mcpServerRef?.services?.unifiedOAuth;
                if (!svc || typeof svc.flushAllRedis !== 'function') {
                    return res.status(500).json({ error: 'Redis flush unavailable' });
                }
                await svc.flushAllRedis();
                res.json({ success: true, message: 'Redis FLUSHALL executed' });
            } catch (e) {
                res.status(500).json({ error: 'Failed to flush Redis', detail: String(e?.message || e) });
            }
        });

        // Admin: List all Hydra clients
        this.router.get('/api/admin/hydra/clients', this.requireAuth.bind(this), async (_req, res) => {
            try {
                const cfg = await this.readLocalYaml();
                const base = `http://${cfg.hydra.hostname}:${cfg.hydra.admin_port}/admin`;
                const r = await request(`${base}/clients`);
                const txt = await r.body.text();
                let clients = [];
                try { clients = JSON.parse(txt); } catch {}
                res.json({ clients });
            } catch (e) {
                res.status(500).json({ error: 'Failed to list Hydra clients', detail: String(e?.message || e) });
            }
        });

        // Admin: Delete all Hydra clients
        this.router.delete('/api/admin/hydra/clients', this.requireAuth.bind(this), async (_req, res) => {
            try {
                const cfg = await this.readLocalYaml();
                const base = `http://${cfg.hydra.hostname}:${cfg.hydra.admin_port}/admin`;
                const list = await request(`${base}/clients`);
                const listTxt = await list.body.text();
                let clients = [];
                try { clients = JSON.parse(listTxt || '[]'); } catch { clients = []; }
                let deleted = 0; let errors = 0;
                for (const c of clients) {
                    const id = c.client_id || c.id || c.clientId || c.name;
                    if (!id) continue;
                    try {
                        await request(`${base}/clients/${encodeURIComponent(id)}`, { method: 'DELETE' });
                        deleted++;
                    } catch {
                        errors++;
                    }
                }
                res.json({ success: true, deleted, errors });
            } catch (e) {
                res.status(500).json({ error: 'Failed to delete Hydra clients', detail: String(e?.message || e) });
            }
        });

        // Login (dashboard users)
        this.router.post('/login', async (req, res) => {
            try {
                const { email, password, remember } = req.body || {};
                if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
                const user = await this.authenticateUser(email, password);
                req.session.authenticated = true;
                req.session.userEmail = user.email;
                try {
                    if (remember === true || remember === 'true') {
                        // Persistent cookie for 30 days
                        req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
                    } else {
                        // Session-only cookie (expire on browser close)
                        req.session.cookie.expires = false;
                        delete req.session.cookie.maxAge;
                    }
                } catch {}
                req.session.save(err => {
                    if (err) return res.status(500).json({ error: 'Session save failed' });
                    res.json({ success: true, remember: !!(remember === true || remember === 'true') });
                });
            } catch (e) {
                res.status(401).json({ error: e.message });
            }
        });
    }

    // Hash generation for UI helpers
    setupHashGenerationRoute() {
        this.router.post('/api/generate-hash', this.requireAuth.bind(this), (req, res) => {
            try {
                const len = Number((req.body && req.body.length) || 32) || 32;
                const hash = this.generateRandomHash(len);
                res.json({ hash });
            } catch (e) {
                res.status(500).json({ error: 'Failed to generate hash' });
            }
        });
    }

    // New routes for full-file operations (client assembles full objects/strings)
    setupFullFileRoutes() {
        // Return raw YAML and parsed object for each configured file
        this.router.get('/api/files-data', this.requireAuth.bind(this), async (_req, res) => {
            try {
                const filesCfg = this.config?.dashboard?.configs?.files || [];
                const result = [];
                for (const f of filesCfg) {
                    const location = f.location;
                    const content = await fs.readFile(location, 'utf8');
                    let obj = null;
                    try { obj = yaml.parse(content); } catch {}
                    result.push({ name: f.name, path: location, content, obj });
                }
                res.json({ files: result });
            } catch (e) {
                res.status(500).json({ error: 'Failed to load files', detail: String(e?.message || e) });
            }
        });

        // Save a single file, provided as full YAML string or object
        this.router.post('/save-full', this.requireAuth.bind(this), async (req, res) => {
            try {
                const { path: filePath, content, obj } = req.body || {};
                if (!filePath || (!content && !obj)) {
                    return res.status(400).json({ error: 'path and content or obj required' });
                }

                const originalText = await fs.readFile(filePath, 'utf8');
                const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
                const backupPath = `${filePath}.bak.${ts}`;
                await fs.writeFile(backupPath, originalText, 'utf8');

                // Prepare object to save; apply MCP users password hashing
                let toWriteObj = null;
                if (obj && typeof obj === 'object') {
                    toWriteObj = await this.applyMcpUserPasswordTransform(obj, originalText);
                } else if (content) {
                    try {
                        const parsed = yaml.parse(content) || {};
                        toWriteObj = await this.applyMcpUserPasswordTransform(parsed, originalText);
                    } catch {
                        // Fall back to raw content if not YAML
                    }
                }

                const newText = toWriteObj ? yaml.stringify(toWriteObj) : (content ?? yaml.stringify(obj ?? {}));
                await fs.writeFile(filePath, newText, 'utf8');

                // Validate parse
                try {
                    yaml.parse(await fs.readFile(filePath, 'utf8'));
                } catch (e) {
                    await fs.writeFile(filePath, originalText, 'utf8');
                    return res.status(400).json({ error: 'Invalid YAML', detail: String(e?.message || e) });
                }

                res.json({ success: true, path: filePath });
            } catch (e) {
                res.status(500).json({ error: 'Failed to save file', detail: String(e?.message || e) });
            }
        });

        // (Preview full-file route removed)
    }

    // Transform MCP users array: hash plain passwords and preserve existing hashes
    async applyMcpUserPasswordTransform(newObj, originalText) {
        try {
            const out = JSON.parse(JSON.stringify(newObj || {}));
            if (!Array.isArray(out.users)) return out; // nothing to do

            // Build map of prior hashes by identifier (name/email)
            let prior = {};
            try {
                const prev = yaml.parse(originalText) || {};
                const prevUsers = Array.isArray(prev.users) ? prev.users : [];
                for (const u of prevUsers) {
                    const key = (u.name || u.email || '').toLowerCase();
                    if (!key) continue;
                    if (u.password_hash) prior[key] = String(u.password_hash);
                }
            } catch {}

            // Walk new users and apply hashing/preservation
            const updated = [];
            for (const u of out.users) {
                const nu = { ...u };
                // Ensure 'email' key is used; migrate from 'name' if needed
                if (!nu.email && nu.name) { nu.email = nu.name; delete nu.name; }
                const key = (nu.email || '').toLowerCase();
                const plain = (nu.password || '').trim();
                delete nu.password; // never persist plain password
                if (plain) {
                    try {
                        nu.password_hash = await bcrypt.hash(plain, 12);
                    } catch (e) {
                        // If hashing fails, fall back to previous hash if present
                        if (key && prior[key]) nu.password_hash = prior[key];
                    }
                } else {
                    // No new password provided: keep existing hash if available
                    if (key && prior[key]) nu.password_hash = prior[key];
                }
                updated.push(nu);
            }
            out.users = updated;
            return out;
        } catch {
            return newObj;
        }
    }

    async readLocalYaml() {
        const localPath = path.resolve(this.appPath + '/config/local.yaml');
        const raw = await fs.readFile(localPath, 'utf8');
        return yaml.parse(raw) || {};
    }
    
    // Authentication middleware
    requireAuth(req, res, next) {
        if (req.session && req.session.authenticated) {
            return next();
        }
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    generateRandomHash(length = 32) {
        // Base64 and trim to requested length
        try {
            return crypto.randomBytes(length).toString('base64').slice(0, length);
        } catch {
            return Math.random().toString(36).slice(2, 2 + length);
        }
    }
    
    // Authenticate user and create session
    async authenticateUser(email, password) {
        const user = this.config.dashboard.users.find(u => u.email === email);
        if (!user) {
            throw new Error('Invalid credentials');
        }
        
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            throw new Error('Invalid credentials');
        }
        
        return user;
    }
    // (preview helpers removed)
    setupUserRoutes() {
        // Get all users
        this.router.get('/api/users', this.requireAuth.bind(this), async (req, res) => {
            try {
                await this.loadDashboardConfig(); // Refresh config
                const users = this.config.dashboard.users.map(user => ({
                    email: user.email
                }));
                res.json(users);
            } catch (error) {
                console.error('Error loading users:', error);
                res.status(500).json({ error: 'Failed to load users' });
            }
        });
        
        // Add new user
        this.router.post('/api/users', this.requireAuth.bind(this), async (req, res) => {
            try {
                const { email, password } = req.body;
                
                if (!email || !password) {
                    return res.status(400).json({ error: 'Email and password required' });
                }
                
                // Check if user already exists
                await this.loadDashboardConfig();
                const existingUser = this.config.dashboard.users.find(u => u.email === email);
                if (existingUser) {
                    return res.status(400).json({ error: 'User already exists' });
                }
                
                // Hash password and add user
                const passwordHash = await bcrypt.hash(password, 12);
                this.config.dashboard.users.push({
                    email,
                    password_hash: passwordHash
                });
                
                await this.saveDashboardConfig();
                res.json({ success: true, message: 'User added successfully' });
            } catch (error) {
                console.error('Error adding user:', error);
                res.status(500).json({ error: 'Failed to add user' });
            }
        });
        
        // Update user
        this.router.put('/api/users/:email', this.requireAuth.bind(this), async (req, res) => {
            try {
                const originalEmail = decodeURIComponent(req.params.email);
                const { email, password } = req.body;
                
                if (!email) {
                    return res.status(400).json({ error: 'Email required' });
                }
                
                await this.loadDashboardConfig();
                const userIndex = this.config.dashboard.users.findIndex(u => u.email === originalEmail);
                if (userIndex === -1) {
                    return res.status(404).json({ error: 'User not found' });
                }
                
                // Update email
                this.config.dashboard.users[userIndex].email = email;
                
                // Update password if provided
                if (password) {
                    this.config.dashboard.users[userIndex].password_hash = await bcrypt.hash(password, 12);
                }
                
                await this.saveDashboardConfig();
                res.json({ success: true, message: 'User updated successfully' });
            } catch (error) {
                console.error('Error updating user:', error);
                res.status(500).json({ error: 'Failed to update user' });
            }
        });
        
        // Delete user
        this.router.delete('/api/users/:email', this.requireAuth.bind(this), async (req, res) => {
            try {
                const email = decodeURIComponent(req.params.email);
                
                // Prevent deletion of current user
                if (email === req.session.userEmail) {
                    return res.status(400).json({ error: 'Cannot delete your own account' });
                }
                
                await this.loadDashboardConfig();
                const userIndex = this.config.dashboard.users.findIndex(u => u.email === email);
                if (userIndex === -1) {
                    return res.status(404).json({ error: 'User not found' });
                }
                
                // Prevent deletion if only one user remains
                if (this.config.dashboard.users.length === 1) {
                    return res.status(400).json({ error: 'Cannot delete the last user' });
                }
                
                this.config.dashboard.users.splice(userIndex, 1);
                await this.saveDashboardConfig();
                res.json({ success: true, message: 'User deleted successfully' });
            } catch (error) {
                console.error('Error deleting user:', error);
                res.status(500).json({ error: 'Failed to delete user' });
            }
        });
    }
    
    setupRestartRoutes() {
        // Execute service restart
        this.router.post('/api/restart-service', this.requireAuth.bind(this), async (req, res) => {
            try {
                const { serviceName, restartCommand } = req.body || {};
                
                if (!serviceName || !restartCommand) {
                    return res.status(400).json({ error: 'Service name and restart command are required' });
                }
                
                console.log(`🔄 Restarting service: ${serviceName} with command: ${restartCommand}`);
                
                // Special handling for MCP Server configuration: internal reload
                if (serviceName === 'MCP Server configuration' || String(restartCommand).startsWith('internal:reload-mcp')) {
                    try {
                        if (!this.mcpServerRef || typeof this.mcpServerRef.reloadMcpAndOAuth !== 'function') {
                            return res.status(500).json({ error: 'Reload function not available' });
                        }
                        await this.mcpServerRef.reloadMcpAndOAuth();
                        return res.json({ success: true, message: 'MCP and OAuth reloaded' });
                    } catch (e) {
                        console.error('❌ Internal reload failed:', e);
                        return res.status(500).json({ error: 'Internal reload failed', detail: String(e?.message || e) });
                    }
                }

                // Hydra restart is hardcoded for safety
                const isHydra = serviceName.toLowerCase().includes('hydra');
                const cmd = isHydra ? 'supervisorctl restart hydra' : restartCommand;
                
                try {
                    const { stdout, stderr } = await execAsync(cmd);
                    console.log(`✅ Service restart completed for ${serviceName} (cmd: ${cmd})`);
                    if (stdout) console.log('Restart stdout:', stdout);
                    if (stderr) console.log('Restart stderr:', stderr);
                    res.json({ 
                        success: true, 
                        message: `${serviceName} restarted successfully`
                    });
                } catch (execError) {
                    console.error(`❌ Service restart failed for ${serviceName}:`, execError);
                    res.status(500).json({ 
                        error: `Failed to restart ${serviceName}: ${execError.message}`
                    });
                }
                
            } catch (error) {
                console.error('Error in restart service:', error);
                res.status(500).json({ error: 'Internal server error during restart' });
            }
        });
        
        // Get services that need restart after config changes
        this.router.get('/api/restart-status', this.requireAuth.bind(this), async (req, res) => {
            try {
                // This would be populated after a config save
                // For now, return empty array
                res.json({ servicesNeedingRestart: [] });
            } catch (error) {
                console.error('Error getting restart status:', error);
                res.status(500).json({ error: 'Failed to get restart status' });
            }
        });

        // List services that can be restarted
        this.router.get('/api/services-with-restart', this.requireAuth.bind(this), async (req, res) => {
            try {
                // Always reload dashboard config to reflect latest changes
                await this.loadDashboardConfig();

                const files = (this.config?.dashboard?.configs?.files || []);
                const services = [];

                for (const f of files) {
                    if (!f?.name) continue;
                    if (f.name === 'MCP Server configuration') {
                        services.push({ name: f.name, restartCommand: 'internal:reload-mcp' });
                    } else if (f.name.toLowerCase().includes('hydra')) {
                        services.push({ name: f.name, restartCommand: 'supervisorctl restart hydra' });
                    }
                }

                // Ensure MCP reload goes last
                services.sort((a, b) => {
                    const isMcpA = a.name === 'MCP Server configuration';
                    const isMcpB = b.name === 'MCP Server configuration';
                    return (isMcpA === isMcpB) ? 0 : (isMcpA ? 1 : -1);
                });

                res.json({ services });
            } catch (error) {
                console.error('Error listing services with restart:', error);
                res.status(500).json({ error: 'Failed to list services' });
            }
        });

        // Explicit endpoint to trigger internal MCP+OAuth reload (used by UI if needed)
        this.router.post('/api/reload-mcp', this.requireAuth.bind(this), async (_req, res) => {
            try {
                if (!this.mcpServerRef || typeof this.mcpServerRef.reloadMcpAndOAuth !== 'function') {
                    return res.status(500).json({ error: 'Reload function not available' });
                }
                await this.mcpServerRef.reloadMcpAndOAuth();
                res.json({ success: true });
            } catch (e) {
                res.status(500).json({ error: 'Internal reload failed', detail: String(e?.message || e) });
            }
        });
    }

    // (Preview config route removed)

    // Version/timestamp endpoint for UI to verify fresh server
    setupVersionRoute() {
        this.router.get('/api/version', async (_req, res) => {
            try {
                const serverStart = new Date(Date.now() - Math.floor(process.uptime() * 1000)).toISOString();
                // Try to read package version
                let appVersion = 'unknown';
                try {
                    const pkgPath = path.resolve(this.appPath, 'package.json');
                    const pkgRaw = await fs.readFile(pkgPath, 'utf8');
                    appVersion = JSON.parse(pkgRaw)?.version || 'unknown';
                } catch {}

                // Include useful file mtimes to help spot stale deployments
                let templateMtime = null;
                let serviceMtime = null;
                try {
                    const t = await fs.stat(path.join(process.cwd(), 'templates', 'dashboard.html'));
                    templateMtime = t.mtime.toISOString();
                } catch {}
                try {
                    const s = await fs.stat(path.join(this.appPath, 'services', 'dashboard-service.js'));
                    serviceMtime = s.mtime.toISOString();
                } catch {}

                res.json({
                    appVersion,
                    node: process.version,
                    serverStart,
                    uptimeSec: Math.floor(process.uptime()),
                    templateMtime,
                    serviceMtime
                });
            } catch (e) {
                res.json({ error: 'version_unavailable', detail: String(e?.message || e) });
            }
        });
    }
    
    // Save dashboard configuration
    async saveDashboardConfig() {
        try {
            const configPath = path.resolve(this.appPath + '/config/dashboard.yaml');
            const yamlContent = yaml.stringify(this.config);
            await fs.writeFile(configPath, yamlContent, 'utf8');
            console.log('Dashboard configuration saved successfully');
        } catch (error) {
            console.error('Error saving dashboard config:', error);
            throw error;
        }
    }
    
    getRouter() {
        return this.router;
    }

    
    //
    async shutdown() {
        console.log('Dashboard Service shutting down...');
        // No cleanup needed for dashboard service
    }
}
