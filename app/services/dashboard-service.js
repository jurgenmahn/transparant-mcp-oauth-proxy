import express from 'express';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import yaml from 'yaml';
import session from 'express-session';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export class DashboardService {
    constructor(appPath) {
        this.appPath = appPath;
        this.router = express.Router();
        this.config = {};
        this.setupSession();
        this.setupRoutes();
        this.setupHashGenerationRoute();
        this.setupUserRoutes();
        this.setupRestartRoutes();
        this.setupPreviewRoute();
        this.setupVersionRoute();
    }
    
    setupSession() {
        this.router.use(session({
            secret: process.env.SESSION_SECRET || 'mcp-dashboard-secret-change-in-production',
            resave: false,
            saveUninitialized: false,
            cookie: {
                secure: false, // Set to true if using HTTPS
                httpOnly: true,
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            }
        }));
    }
    
    async initialize() {
        await this.loadDashboardConfig();
        console.log('Dashboard Service initialized');
    }
    
    async loadDashboardConfig() {
        try {
            const configPath = path.resolve(this.appPath + '/config/dashboard.yaml');
            const configContent = await fs.readFile(configPath, 'utf8');
            this.config = yaml.parse(configContent);
            console.log('Dashboard configuration loaded successfully');
        } catch (error) {
            console.error('Error loading dashboard config:', error);
            throw error;
        }
    }
    
    setupRoutes() {
        // Dashboard main page
        this.router.get('/', async (req, res) => {
            try {
                const values = await this.loadCurrentValues();
                const { generalHtml, mcpHtml, hydraHtml } = this.generateTabbedContents(values);
                const templatePath = path.join(process.cwd(), 'templates', 'dashboard.html');
                let html = await fs.readFile(templatePath, 'utf8');
                html = html.replace('{{GENERAL_FORM}}', generalHtml);
                html = html.replace('{{MCP_FORM}}', mcpHtml);
                html = html.replace('{{HYDRA_FORM}}', hydraHtml);
                res.send(html);
            } catch (error) {
                console.error('Error generating dashboard:', error);
                res.status(500).send('Error loading configuration dashboard');
            }
        });
        
        // Authentication status check
        this.router.get('/api/auth-status', (req, res) => {
            if (req.session && req.session.authenticated) {
                res.json({ 
                    authenticated: true, 
                    email: req.session.userEmail 
                });
            } else {
                res.json({ authenticated: false });
            }
        });
        
        // Logout endpoint
        this.router.post('/logout', (req, res) => {
            req.session.destroy((err) => {
                if (err) {
                    console.error('Session destruction error:', err);
                    return res.status(500).json({ error: 'Failed to logout' });
                }
                res.json({ success: true });
            });
        });
        
        // Login endpoint
        this.router.post('/login', async (req, res) => {
            try {
                const { email, password } = req.body;
                
                if (!email || !password) {
                    return res.status(400).json({ error: 'Email and password required' });
                }
                
                const user = await this.authenticateUser(email, password);
                
                // Create session
                req.session.authenticated = true;
                req.session.userEmail = user.email;
                
                res.json({ success: true, message: 'Authentication successful' });
            } catch (error) {
                res.status(401).json({ error: error.message });
            }
        });
        
        // Save configuration
        this.router.post('/save-config', this.requireAuth.bind(this), async (req, res) => {
            try {
                console.log('🔧 Save configuration request received');
                console.log('📝 Form data keys:', Object.keys(req.body));
                console.log('📝 Form data preview:', Object.fromEntries(
                    Object.entries(req.body).slice(0, 3).map(([k, v]) => [k, typeof v === 'string' && v.length > 50 ? v.substring(0, 50) + '...' : v])
                ));
                
                const result = await this.saveConfiguration(req.body);
                
                const response = {
                    success: true, 
                    message: 'Configuration saved successfully',
                    servicesNeedingRestart: result.servicesNeedingRestart,
                    debug: {
                        filesUpdated: result.filesUpdated || [],
                        fieldsUpdated: result.fieldsUpdated || [],
                        formFieldsProcessed: Object.keys(req.body).length,
                        generalFieldsDetected: Object.keys(req.body).filter(k => k.startsWith('general::')).length,
                        totalUpdatesApplied: result.totalUpdatesApplied || 0
                    }
                };
                
                console.log('✅ Save response:', {
                    servicesCount: response.servicesNeedingRestart.length,
                    filesUpdated: response.debug.filesUpdated.length,
                    fieldsUpdated: response.debug.fieldsUpdated.length
                });
                
                res.json(response);
            } catch (error) {
                console.error('❌ Error saving configuration:', error);
                // Surface validation errors clearly to the client
                const message = error?.message || 'Failed to save configuration';
                res.status(400).json({ success: false, error: message, debug: { error: error.message } });
            }
        });
        
        // Get current configuration (API endpoint)
        this.router.get('/api/config', this.requireAuth.bind(this), async (req, res) => {
            try {
                const values = await this.loadCurrentValues();
                res.json(values);
            } catch (error) {
                console.error('Error loading config values:', error);
                res.status(500).json({ error: 'Failed to load configuration' });
            }
        });
        
        // Debug endpoint to see extracted fields per configured file
        this.router.get('/api/debug', this.requireAuth.bind(this), async (req, res) => {
            try {
                const result = [];
                for (const file of (this.config?.dashboard?.configs?.files || [])) {
                    const fields = await this.extractFieldDefinitions(file.location);
                    result.push({ file: file.name, location: file.location, fields, count: fields.length });
                }
                res.json(result);
            } catch (error) {
                console.error('Error in debug:', error);
                res.status(500).json({ error: error.message });
            }
        });
    }
    
    // Authentication middleware
    requireAuth(req, res, next) {
        if (req.session && req.session.authenticated) {
            return next();
        }
        return res.status(401).json({ error: 'Authentication required' });
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
    
    // Parse comment-based field definitions
    parseCommentField(comments) {
        const field = {};
        
        for (const comment of comments) {
            const line = comment.trim();
            if (line.startsWith('friendly_name:')) {
                field.friendly_name = line.substring('friendly_name:'.length).trim();
            } else if (line.startsWith('mandatory:')) {
                field.mandatory = line.substring('mandatory:'.length).trim() === 'true';
            } else if (line.startsWith('allowed_values:')) {
                const values = line.substring('allowed_values:'.length).trim();
                field.allowed_values = values === 'null' ? null : values.split(',').map(v => v.trim());
            } else if (line.startsWith('field_type:')) {
                field.field_type = line.substring('field_type:'.length).trim();
            } else if (line.startsWith('validation:')) {
                const validation = line.substring('validation:'.length).trim();
                field.validation = validation === 'null' ? null : validation;
            } else if (line.startsWith('length:')) {
                field.length = parseInt(line.substring('length:'.length).trim());
            } else if (line.startsWith('help:')) {
                field.help = line.substring('help:'.length).trim();
            } else if (line.startsWith('prepend:')) {
                field.prepend = line.substring('prepend:'.length).trim();
            } else if (line.startsWith('append:')) {
                field.append = line.substring('append:'.length).trim();
            } else if (line.match(/^friendly_name\[(\d+)\]:/)) {
                const index = parseInt(line.match(/^friendly_name\[(\d+)\]:/)[1]);
                if (!field.sub_fields) field.sub_fields = [];
                if (!field.sub_fields[index]) field.sub_fields[index] = {};
                field.sub_fields[index].friendly_name = line.substring(line.indexOf(':') + 1).trim();
            } else if (line.match(/^validation\[(\d+)\]:/)) {
                const index = parseInt(line.match(/^validation\[(\d+)\]:/)[1]);
                if (!field.sub_fields) field.sub_fields = [];
                if (!field.sub_fields[index]) field.sub_fields[index] = {};
                const validation = line.substring(line.indexOf(':') + 1).trim();
                field.sub_fields[index].validation = validation === 'null' ? null : validation;
            } else if (line.match(/^mandatory\[(\d+)\]:/)) {
                const index = parseInt(line.match(/^mandatory\[(\d+)\]:/)[1]);
                if (!field.sub_fields) field.sub_fields = [];
                if (!field.sub_fields[index]) field.sub_fields[index] = {};
                field.sub_fields[index].mandatory = line.substring(line.indexOf(':') + 1).trim() === 'true';
            } else if (line.match(/^help\[(\d+)\]:/)) {
                const index = parseInt(line.match(/^help\[(\d+)\]:/)[1]);
                if (!field.sub_fields) field.sub_fields = [];
                if (!field.sub_fields[index]) field.sub_fields[index] = {};
                field.sub_fields[index].help = line.substring(line.indexOf(':') + 1).trim();
            }
        }
        
        return field;
    }
    
    // Extract field definitions for a file. Prefer dashboard.yaml > fallback to comment parsing
    async extractFieldDefinitions(filePath) {
        try {
            const content = await fs.readFile(filePath, 'utf8');
            
            // Parse the entire file as YAML first to get the actual values
            const yamlData = yaml.parse(content);
            
            // 1) Prefer explicit field definitions from dashboard.yaml (if present)
            const fileCfg = (this.config?.dashboard?.configs?.files || []).find(f => f.location === filePath);
            if (fileCfg && Array.isArray(fileCfg.editable_fields)) {
                return this.buildFieldsFromDashboardConfig(fileCfg.editable_fields, yamlData);
            }

            // 2) Fallback to legacy comment-based extraction in target YAML
            const fields = [];
            const dashboardBlocks = this.findDashboardBlocks(content);
            for (const block of dashboardBlocks) {
                const field = this.parseFieldFromBlock(block, yamlData);
                if (field) fields.push(field);
            }
            return fields;
        } catch (error) {
            console.error(`Error reading file ${filePath}:`, error);
            return [];
        }
    }

    // Build field definitions from dashboard.yaml editable_fields array
    buildFieldsFromDashboardConfig(editableFields, yamlData) {
        const fields = [];
        for (const spec of editableFields) {
            if (!spec || !spec.field) continue;
            const pathSegments = String(spec.field).split('/').filter(Boolean);
            const yaml_key = pathSegments[pathSegments.length - 1];
            const yaml_path = pathSegments.slice(0, -1);

            const field = {
                yaml_key,
                yaml_path,
                friendly_name: spec.friendly_name || yaml_key,
                field_type: spec.field_type || 'textbox',
                mandatory: !!spec.mandatory,
                allowed_values: this.normalizeAllowedValues(spec.allowed_values),
                validation: spec.validation ?? null,
                length: spec.length ?? null,
                help: spec.help ?? null,
                prepend: spec.prepend ?? null,
                append: spec.append ?? null,
                sub_fields: Array.isArray(spec.sub_fields) ? spec.sub_fields : []
            };

            field.current_value = this.getValueFromYamlPath(yamlData, yaml_path, yaml_key);
            fields.push(field);
        }
        return fields;
    }

    normalizeAllowedValues(values) {
        if (!values || values === 'null') return null;
        if (Array.isArray(values)) return values;
        // Allow comma-separated string
        if (typeof values === 'string') return values.split(',').map(v => v.trim()).filter(Boolean);
        return null;
    }
    
    // Find all DASHBOARD comment blocks
    findDashboardBlocks(content) {
        const blocks = [];
        const lines = content.split('\n');
        
        for (let i = 0; i < lines.length; i++) {
            if (lines[i].trim() === '# DASHBOARD') {
                const block = {
                    startLine: i,
                    comments: [],
                    configLine: null,
                    yamlKey: null,
                    yamlPath: []
                };
                
                // Collect comment lines - keep the original comment with # removed
                let j = i + 1;
                while (j < lines.length && lines[j].trim().startsWith('#')) {
                    const comment = lines[j].trim();
                    if (comment && comment !== '#') {
                        block.comments.push(comment);
                    }
                    j++;
                }
                
                // Find the config line
                while (j < lines.length && (lines[j].trim() === '' || lines[j].trim().startsWith('#'))) {
                    j++;
                }
                
                if (j < lines.length) {
                    block.configLine = lines[j];
                    block.yamlKey = this.extractYamlKey(lines[j]);
                    block.yamlPath = this.buildYamlPath(lines, j);
                    
                    if (block.yamlKey) {
                        blocks.push(block);
                    }
                }
            }
        }
        
        return blocks;
    }
    
    // Parse field from a DASHBOARD block
    parseFieldFromBlock(block, yamlData) {
        const field = {
            yaml_key: block.yamlKey,
            yaml_path: block.yamlPath,
            friendly_name: null,
            field_type: 'textbox',
            mandatory: false,
            allowed_values: null,
            validation: null,
            length: null,
            help: null,
            prepend: null,
            append: null,
            sub_fields: []
        };
        
        // Parse comments to extract field properties
        console.log(`🔍 Field ${block.yamlKey}: Found ${block.comments.length} comments:`, block.comments);
        for (const comment of block.comments) {
            this.parseCommentLine(comment, field);
        }
        console.log(`📝 Field ${block.yamlKey}: friendly_name=${field.friendly_name}, field_type=${field.field_type}`);
        
        // Get the current value from parsed YAML
        field.current_value = this.getValueFromYamlPath(yamlData, field.yaml_path, field.yaml_key);
        
        return field;
    }
    
    // Parse a single comment line and update field properties
    parseCommentLine(comment, field) {
        // Remove # prefix and clean up
        let trimmed = comment.trim();
        if (trimmed.startsWith('#')) {
            trimmed = trimmed.substring(1).trim();
        }
        
        if (trimmed.startsWith('friendly_name:')) {
            field.friendly_name = trimmed.substring('friendly_name:'.length).trim();
        } else if (trimmed.startsWith('field_type:')) {
            field.field_type = trimmed.substring('field_type:'.length).trim();
        } else if (trimmed.startsWith('mandatory:')) {
            field.mandatory = trimmed.substring('mandatory:'.length).trim() === 'true';
        } else if (trimmed.startsWith('allowed_values:')) {
            const values = trimmed.substring('allowed_values:'.length).trim();
            if (values !== 'null' && values !== '') {
                field.allowed_values = values.split(',').map(v => v.trim());
            }
        } else if (trimmed.startsWith('validation:')) {
            const validation = trimmed.substring('validation:'.length).trim();
            if (validation !== 'null' && validation !== '') {
                field.validation = validation;
            }
        } else if (trimmed.startsWith('length:')) {
            field.length = parseInt(trimmed.substring('length:'.length).trim());
        } else if (trimmed.startsWith('help:')) {
            field.help = trimmed.substring('help:'.length).trim();
        } else if (trimmed.startsWith('prepend:')) {
            field.prepend = trimmed.substring('prepend:'.length).trim();
        } else if (trimmed.startsWith('append:')) {
            field.append = trimmed.substring('append:'.length).trim();
        } else if (trimmed.match(/^friendly_name\[(\d+)\]:/)) {
            const match = trimmed.match(/^friendly_name\[(\d+)\]:/);
            const index = parseInt(match[1]);
            if (!field.sub_fields[index]) field.sub_fields[index] = {};
            field.sub_fields[index].friendly_name = trimmed.substring(trimmed.indexOf(':') + 1).trim();
        } else if (trimmed.match(/^validation\[(\d+)\]:/)) {
            const match = trimmed.match(/^validation\[(\d+)\]:/);
            const index = parseInt(match[1]);
            if (!field.sub_fields[index]) field.sub_fields[index] = {};
            const validation = trimmed.substring(trimmed.indexOf(':') + 1).trim();
            field.sub_fields[index].validation = validation === 'null' ? null : validation;
        } else if (trimmed.match(/^mandatory\[(\d+)\]:/)) {
            const match = trimmed.match(/^mandatory\[(\d+)\]:/);
            const index = parseInt(match[1]);
            if (!field.sub_fields[index]) field.sub_fields[index] = {};
            field.sub_fields[index].mandatory = trimmed.substring(trimmed.indexOf(':') + 1).trim() === 'true';
        } else if (trimmed.match(/^help\[(\d+)\]:/)) {
            const match = trimmed.match(/^help\[(\d+)\]:/);
            const index = parseInt(match[1]);
            if (!field.sub_fields[index]) field.sub_fields[index] = {};
            field.sub_fields[index].help = trimmed.substring(trimmed.indexOf(':') + 1).trim();
        }
    }
    
    // Build YAML path for a line
    buildYamlPath(lines, lineIndex) {
        const path = [];
        const currentIndent = lines[lineIndex].search(/\S/);
        let targetIndent = currentIndent;
        
        // Walk backwards to build the path properly
        for (let i = lineIndex - 1; i >= 0; i--) {
            const line = lines[i];
            if (line.trim() === '' || line.trim().startsWith('#')) continue;
            
            const indent = line.search(/\S/);
            
            // Only consider lines that are actual parent levels
            if (indent < targetIndent) {
                const match = line.match(/^\s*([^:]+):/);
                if (match) {
                    path.unshift(match[1].trim());
                    targetIndent = indent; // Update target to find the next parent level
                }
            }
        }
        
        return path;
    }
    
    // Get value from YAML data using path
    getValueFromYamlPath(yamlData, path, key) {
        let current = yamlData;
        
        for (const segment of path) {
            if (current && typeof current === 'object' && segment in current) {
                current = current[segment];
            } else {
                return null;
            }
        }
        
        if (current && typeof current === 'object' && key in current) {
            return current[key];
        }
        
        return null;
    }
    
    // Extract YAML key from config line
    extractYamlKey(line) {
        const match = line.match(/^\s*([^:]+):\s*(.*)$/);
        return match ? match[1].trim() : null;
    }
    
    // Get YAML path for a line (parent keys)
    getYamlPath(lines, lineIndex) {
        const path = [];
        const currentIndent = lines[lineIndex].search(/\S/);
        
        for (let i = lineIndex - 1; i >= 0; i--) {
            const line = lines[i];
            if (line.trim() === '' || line.trim().startsWith('#')) continue;
            
            const indent = line.search(/\S/);
            const match = line.match(/^\s*([^:]+):/);
            
            if (match && indent < currentIndent) {
                path.unshift(match[1].trim());
            }
        }
        
        return path.join('.');
    }
    
    // Extract value from config line and handle arrays/objects
    extractValueFromConfigLine(line, lines, lineIndex) {
        const match = line.match(/^\s*[^:]+:\s*(.*)$/);
        if (!match) return null;
        
        const value = match[1].trim();
        
        // If line ends with just the key (array or object follows)
        if (value === '' || value === '|') {
            // Parse the YAML value using actual YAML parser
            return this.parseYamlSection(lines, lineIndex);
        }
        
        return value;
    }
    
    // Parse YAML section using proper YAML parser
    parseYamlSection(lines, lineIndex) {
        try {
            // Get the key name from the current line
            const keyLine = lines[lineIndex];
            const keyMatch = keyLine.match(/^\s*([^:]+):/);
            if (!keyMatch) return null;
            
            const keyName = keyMatch[1].trim();
            const keyIndent = keyLine.search(/\S/);
            
            // Collect all lines that belong to this key
            const sectionLines = [keyLine];
            let i = lineIndex + 1;
            
            while (i < lines.length) {
                const line = lines[i];
                if (line.trim() === '' || line.trim().startsWith('#')) {
                    sectionLines.push(line);
                    i++;
                    continue;
                }
                
                const indent = line.search(/\S/);
                if (indent <= keyIndent) break;
                
                sectionLines.push(line);
                i++;
            }
            
            // Parse the section as YAML
            const yamlText = sectionLines.join('\n');
            const parsed = yaml.parse(yamlText);
            
            return parsed[keyName];
        } catch (error) {
            console.error('Error parsing YAML section:', error);
            return null;
        }
    }
    
    // Load current values directly from config files
    async loadCurrentValues() {
        const values = {};
        
        for (const file of this.config.dashboard.configs.files) {
            const filePath = file.location;
            
            try {
                const fields = await this.extractFieldDefinitions(filePath);
                
                for (const field of fields) {
                    // Create a truly unique key using both friendly_name and yaml_key to prevent overwrites
                    const fieldIdentifier = field.friendly_name || field.yaml_key;
                    const uniqueKey = `${file.name}::${fieldIdentifier}::${field.yaml_key}`;
                    
                    values[uniqueKey] = {
                        file: file.name,
                        filePath: filePath,
                        field: field,
                        currentValue: field.current_value
                    };
                }
            } catch (error) {
                console.error(`Error processing file ${file.name}:`, error);
            }
        }
        
        return values;
    }
    
    
    // Generate form content HTML
    generateFormContent(values) {
        const sections = {};
        
        // Group by file
        Object.entries(values).forEach(([, data]) => {
            if (!sections[data.file]) {
                sections[data.file] = [];
            }
            sections[data.file].push(data);
        });
        
        let formHtml = '';
        
        // Find fields that appear in multiple files - show them in general section
        const fieldCounts = {};
        Object.values(values).forEach(data => {
            const friendlyName = data.field.friendly_name;
            if (friendlyName && friendlyName.trim() !== '') {
                fieldCounts[friendlyName] = (fieldCounts[friendlyName] || 0) + 1;
            }
        });
        
        const generalFields = Object.keys(fieldCounts).filter(name => fieldCounts[name] > 1);
        
        // Generate general section for common fields
        if (generalFields.length > 0) {
            formHtml += `
                <div class="section general-section">
                    <div class="section-header">General Settings</div>
                    <div class="section-content">
            `;
            
            generalFields.forEach(friendlyName => {
                const firstData = Object.values(values).find(data => data.field.friendly_name === friendlyName);
                formHtml += this.generateFieldHtml(`general::${friendlyName}`, firstData);
            });
            
            formHtml += '</div></div>';
        }
        
        // Generate sections for each file
        Object.entries(sections).forEach(([fileName, fields]) => {
            formHtml += `
                <div class="section">
                    <div class="section-header">${fileName}</div>
                    <div class="section-content">
            `;
            
            fields.forEach(data => {
                // Skip if this field is already in general section
                if (!generalFields.includes(data.field.friendly_name)) {
                    const fieldKey = Object.keys(values).find(key => values[key] === data);
                    formHtml += this.generateFieldHtml(fieldKey, data);
                }
            });
            
            formHtml += '</div></div>';
        });
        
        return formHtml;
    }

    // Build tab-specific contents for General, MCP and Hydra
    generateTabbedContents(values) {
        // Group values by file for easy processing
        const sections = {};
        Object.entries(values).forEach(([, data]) => {
            if (!sections[data.file]) sections[data.file] = [];
            sections[data.file].push(data);
        });

        // Compute general fields (friendly names appearing in multiple files)
        const fieldCounts = {};
        Object.values(values).forEach(data => {
            const friendlyName = data.field.friendly_name;
            if (friendlyName && friendlyName.trim() !== '') {
                fieldCounts[friendlyName] = (fieldCounts[friendlyName] || 0) + 1;
            }
        });
        const generalFields = Object.keys(fieldCounts).filter(name => fieldCounts[name] > 1);

        // General HTML
        let generalHtml = '';
        if (generalFields.length > 0) {
            generalHtml += `
                <div class="section general-section">
                    <div class="section-header">General Settings</div>
                    <div class="section-content expanded">
            `;
            generalFields.forEach(friendlyName => {
                const firstData = Object.values(values).find(data => data.field.friendly_name === friendlyName);
                generalHtml += this.generateFieldHtml(`general::${friendlyName}`, firstData);
            });
            generalHtml += '</div></div>';
        } else {
            generalHtml += `
                <div class="section general-section">
                    <div class="section-header">General Settings</div>
                    <div class="section-content expanded">
                        <div class="field-group"><em>No general fields detected.</em></div>
                    </div>
                </div>
            `;
        }

        // Helper to render a file-based section excluding general fields
        const renderFileSection = (fileName) => {
            const items = (sections[fileName] || []).filter(data => !generalFields.includes(data.field.friendly_name));
            let html = '';
            html += `
                <div class="section">
                    <div class="section-header">${fileName}</div>
                    <div class="section-content expanded">
            `;
            items.forEach(data => {
                const fieldKey = Object.keys(values).find(key => values[key] === data);
                html += this.generateFieldHtml(fieldKey, data);
            });
            html += '</div></div>';
            return html;
        };

        // Determine canonical file names from dashboard.yaml
        const mcpFileName = (this.config?.dashboard?.configs?.files || []).find(f => f.location?.includes('local.yaml'))?.name || 'MCP Server configuration';
        const hydraFileName = (this.config?.dashboard?.configs?.files || []).find(f => f.location?.includes('/hydra/'))?.name || 'Hydra configuration';

        const mcpHtml = renderFileSection(mcpFileName);
        const hydraHtml = renderFileSection(hydraFileName);

        return { generalHtml, mcpHtml, hydraHtml };
    }
    
    // Generate HTML for individual field
    generateFieldHtml(fieldKey, data) {
        const { field, currentValue } = data;
        let fieldHtml = `<div class="field-group">`;
        
        const label = field.friendly_name || field.yaml_key;
        fieldHtml += `<label for="${fieldKey}">${label}`;
        
        if (field.mandatory) {
            fieldHtml += ' <span class="required">*</span>';
        }
        
        if (field.help) {
            fieldHtml += ` <span class="help-icon" title="${field.help}">ⓘ</span>`;
        }
        
        fieldHtml += '</label>';
        
        // Handle different field types
        if (field.field_type && field.field_type.startsWith('array')) {
            fieldHtml += this.generateArrayField(fieldKey, field, currentValue);
        } else if (field.allowed_values && field.allowed_values.length > 0) {
            // Dropdown for allowed values
            fieldHtml += `<select name="${fieldKey}" id="${fieldKey}"`;
            if (field.mandatory) fieldHtml += ' required';
            fieldHtml += '>';
            
            if (!field.mandatory) {
                fieldHtml += '<option value="">-- Select --</option>';
            }
            
            const displayValue = this.getDisplayValue(currentValue, field);
            field.allowed_values.forEach(option => {
                const selected = displayValue === option ? 'selected' : '';
                fieldHtml += `<option value="${option}" ${selected}>${option}</option>`;
            });
            fieldHtml += '</select>';
        } else {
            switch (field.field_type) {
                case 'dropdown':
                    // Dropdown should have allowed_values, fallback to textbox
                    fieldHtml += `<input type="text" name="${fieldKey}" id="${fieldKey}" value="${this.getDisplayValue(currentValue, field)}"`;
                    if (field.validation) fieldHtml += ` pattern="${this.sanitizeHtmlPattern(field.validation)}"`;
                    if (field.mandatory) fieldHtml += ' required';
                    fieldHtml += '>';
                    break;
                    
                case 'password':
                    const hasExistingPassword = currentValue && currentValue.trim() !== '';
                    fieldHtml += `<div class="password-field">`;
                    if (hasExistingPassword) {
                        // Existing password - disabled by default with edit button
                        fieldHtml += `<input type="password" name="${fieldKey}" id="${fieldKey}" placeholder="Password unchanged" disabled>`;
                        fieldHtml += `<button type="button" class="edit-password-btn" onclick="togglePasswordEdit('${fieldKey}', true)">Edit</button>`;
                        fieldHtml += `<button type="button" class="cancel-password-btn" onclick="togglePasswordEdit('${fieldKey}', false)" style="display: none;">Cancel</button>`;
                    } else {
                        // New password - enabled and required
                        fieldHtml += `<input type="password" name="${fieldKey}" id="${fieldKey}" placeholder="Enter password"`;
                        if (field.mandatory) fieldHtml += ' required';
                        fieldHtml += '>';
                    }
                    fieldHtml += `</div>`;
                    break;
                    
                case 'hash':
                    fieldHtml += `<div class="hash-field">`;
                    fieldHtml += `<input type="text" name="${fieldKey}" id="${fieldKey}" value="${currentValue || ''}" readonly>`;
                    fieldHtml += `<button type="button" onclick="generateHash('${fieldKey}', ${field.length || 32})">Generate New</button>`;
                    fieldHtml += `</div>`;
                    break;
                    
                case 'multiline':
                    fieldHtml += `<textarea name="${fieldKey}" id="${fieldKey}" rows="4"`;
                    if (field.mandatory) fieldHtml += ' required';
                    fieldHtml += `>${currentValue || ''}</textarea>`;
                    break;
                    
                case 'textbox':
                default:
                    fieldHtml += `<input type="text" name="${fieldKey}" id="${fieldKey}" value="${this.getDisplayValue(currentValue, field)}"`;
                    if (field.validation) fieldHtml += ` pattern="${this.sanitizeHtmlPattern(field.validation)}"`;
                    if (field.mandatory) fieldHtml += ' required';
                    fieldHtml += '>';
                    break;
            }
        }
        
        fieldHtml += '</div>';
        return fieldHtml;
    }
    
    // Get display value (removing prepend/append for UI)
    getDisplayValue(currentValue, field) {
        if (!currentValue) return '';
        
        let value = currentValue.toString();
        
        // Remove prepend if it exists
        if (field.prepend && value.startsWith(field.prepend)) {
            value = value.substring(field.prepend.length);
        }
        
        // Remove append if it exists
        if (field.append && value.endsWith(field.append)) {
            value = value.substring(0, value.length - field.append.length);
        }
        
        return value;
    }
    
    // Generate HTML for array fields
    generateArrayField(fieldKey, field, currentValue) {
        const arrayType = field.field_type.match(/array\[(.+)\]/)[1];
        
        if (arrayType.includes(':')) {
            // Complex array with subtypes (e.g., array[textbox:name,textbox:startup_command])
            return this.generateComplexArrayField(fieldKey, field, currentValue, arrayType);
        } else {
            // Simple array (e.g., array[textbox])
            return this.generateSimpleArrayField(fieldKey, field, currentValue, arrayType);
        }
    }
    
    // Generate simple array field (just one type)
    generateSimpleArrayField(fieldKey, field, currentValue, arrayType) {
        let html = `<div class="array-field" id="${fieldKey}_container">`;
        
        const values = Array.isArray(currentValue) ? currentValue : [];
        
        if (values.length === 0) {
            // Add at least one empty field
            values.push('');
        }
        
        values.forEach((value, index) => {
            html += `<div class="array-item" data-index="${index}">`;
            
            switch (arrayType) {
                case 'textbox':
                    html += `<input type="text" name="${fieldKey}[${index}]" value="${value || ''}" placeholder="Enter value">`;
                    break;
                case 'hash':
                    html += `<div class=\"hash-field\">`;
                    html += `<input type=\"text\" name=\"${fieldKey}[${index}]\" id=\"${fieldKey}[${index}]\" value=\"${value || ''}\" readonly>`;
                    html += `<button type=\"button\" onclick=\"generateHash('${fieldKey}[${index}]', 32)\">Generate</button>`;
                    html += `</div>`;
                    break;
                case 'multiline':
                    html += `<textarea name="${fieldKey}[${index}]" rows="3" placeholder="Enter value">${value || ''}</textarea>`;
                    break;
                default:
                    html += `<input type="text" name="${fieldKey}[${index}]" value="${value || ''}" placeholder="Enter value">`;
            }
            
            html += `<button type="button" class="remove-array-item" onclick="removeArrayItem(this)">Remove</button>`;
            html += `</div>`;
        });
        
        html += `</div>`;
        html += `<button type="button" class="add-array-item" onclick="addArrayItem('${fieldKey}')">Add Item</button>`;
        
        return html;
    }
    
    // Generate complex array field (multiple subtypes)
    generateComplexArrayField(fieldKey, field, currentValue, arrayType) {
        const subTypes = arrayType.split(',').map(type => {
            const parts = type.split(':');
            return { type: parts[0], name: parts[1] || parts[0] };
        });
        
        let html = `<div class="array-field" id="${fieldKey}_container">`;
        
        const values = Array.isArray(currentValue) ? currentValue : [];
        
        if (values.length === 0) {
            // Add at least one empty item
            values.push({});
        }
        
        values.forEach((item, index) => {
            html += this.generateComplexArrayItem(fieldKey, subTypes, item, index, field);
        });
        
        html += `</div>`;
        html += `<button type="button" class="add-array-item" onclick="addArrayItem('${fieldKey}')">Add Item</button>`;
        
        return html;
    }
    
    // Generate HTML for individual complex array item
    generateComplexArrayItem(fieldKey, subTypes, item, index, field) {
        let html = `<div class="array-item" data-index="${index}">`;
        
        subTypes.forEach((subType, subIndex) => {
            const subFieldKey = `${fieldKey}[${index}][${subType.name}]`;
            const subFieldName = field.sub_fields && field.sub_fields[subIndex] ? 
                field.sub_fields[subIndex].friendly_name : subType.name;
            
            // Extract the actual value (not "name: value" but just "value")
            let subValue = '';
            if (typeof item === 'object' && item !== null) {
                // Handle field mapping for users (config uses 'email' but field expects 'name')
                if (subType.name === 'name' && item.email) {
                    subValue = item.email;
                } else {
                    subValue = item[subType.name] || '';
                }
            } else if (subIndex === 0 && typeof item === 'string') {
                // For first field, if item is a string, use it directly
                subValue = item;
            }
            
            html += `<div class="sub-field">`;
            html += `<label>${subFieldName}`;
            
            // Add help icon if help text exists for this sub-field
            if (field.sub_fields && field.sub_fields[subIndex] && field.sub_fields[subIndex].help) {
                html += ` <span class="help-icon" title="${field.sub_fields[subIndex].help}">ⓘ</span>`;
            }
            
            html += `</label>`;
            
            switch (subType.type) {
                case 'textbox':
                    html += `<input type="text" name="${subFieldKey}" value="${subValue}"`;
                    if (field.sub_fields && field.sub_fields[subIndex] && field.sub_fields[subIndex].validation) {
                        html += ` pattern="${this.sanitizeHtmlPattern(field.sub_fields[subIndex].validation)}"`;
                    }
                    if (field.sub_fields && field.sub_fields[subIndex] && field.sub_fields[subIndex].mandatory) {
                        html += ' required';
                    }
                    html += '>';
                    break;
                    
                case 'password':
                    const hasExistingSubPassword = subValue && subValue.trim() !== '';
                    html += `<div class="password-field">`;
                    if (hasExistingSubPassword) {
                        // Existing password - disabled by default with edit button
                        html += `<input type="password" name="${subFieldKey}" id="${subFieldKey}" placeholder="Password unchanged" disabled>`;
                        html += `<button type="button" class="edit-password-btn" onclick="togglePasswordEdit('${subFieldKey}', true)">Edit</button>`;
                        html += `<button type="button" class="cancel-password-btn" onclick="togglePasswordEdit('${subFieldKey}', false)" style="display: none;">Cancel</button>`;
                    } else {
                        // New password - enabled and required
                        html += `<input type="password" name="${subFieldKey}" id="${subFieldKey}" placeholder="Enter password"`;
                        if (field.sub_fields && field.sub_fields[subIndex] && field.sub_fields[subIndex].mandatory) {
                            html += ' required';
                        }
                        html += '>';
                    }
                    html += `</div>`;
                    break;
                    
                case 'hash':
                    html += `<div class="hash-field">`;
                    html += `<input type="text" name="${subFieldKey}" value="${subValue}" readonly>`;
                    html += `<button type="button" onclick="generateHash('${subFieldKey}', 32)">Generate</button>`;
                    html += `</div>`;
                    break;
                    
                case 'multiline':
                    html += `<textarea name="${subFieldKey}" rows="3">${subValue}</textarea>`;
                    break;
                    
                case 'array[textbox]':
                    // Handle sub-array fields like options in mcp_services
                    let arrayValues = Array.isArray(subValue) ? subValue : (subValue ? subValue.split(',').map(v => v.trim()) : []);
                    html += `<div class="array-field" id="${subFieldKey}_container">`;
                    
                    if (arrayValues.length === 0) {
                        arrayValues.push(''); // Add at least one empty item
                    }
                    
                    arrayValues.forEach((arrayItem, arrayIndex) => {
                        html += `<div class="array-item" data-index="${arrayIndex}">`;
                        html += `<input type="text" name="${subFieldKey}[${arrayIndex}]" value="${arrayItem}" placeholder="Enter value">`;
                        html += `<button type="button" class="remove-array-item" onclick="removeArrayItem(this)">Remove</button>`;
                        html += `</div>`;
                    });
                    
                    html += `</div>`;
                    html += `<button type="button" class="add-array-item" onclick="addArrayItem('${subFieldKey}')">Add Item</button>`;
                    break;
                    
                default:
                    html += `<input type="text" name="${subFieldKey}" value="${subValue}">`;
            }
            
            html += `</div>`;
        });
        
        html += `<button type="button" class="remove-array-item" onclick="removeArrayItem(this)">Remove</button>`;
        html += `</div>`;
        
        return html;
    }
    
    // Save configuration files
    async saveConfiguration(formData) {
        console.log('🔧 saveConfiguration called with', Object.keys(formData).length, 'form fields');
        
        const values = await this.loadCurrentValues();
        console.log('📋 Loaded', Object.keys(values).length, 'current field values');
        
        // Group form data by file
        const fileUpdates = {};
        const debugInfo = {
            filesUpdated: [],
            fieldsUpdated: [],
            totalUpdatesApplied: 0,
            processedFields: []
        };
        
        // Aggregate bracketed array inputs under their base key so arrays (e.g., mcp_services options/install) are captured
        const aggregated = new Map();
        Object.entries(formData).forEach(([rawKey, val]) => {
            const baseKey = rawKey.replace(/\[.*$/, '');
            const bracket = rawKey.startsWith(baseKey) ? rawKey.substring(baseKey.length) : '';
            if (!aggregated.has(baseKey)) aggregated.set(baseKey, { scalar: undefined, map: {} });
            if (bracket) {
                aggregated.get(baseKey).map[bracket] = val;
            } else {
                aggregated.get(baseKey).scalar = val;
            }
            let valuePreview;
            if (typeof val === 'string') {
                valuePreview = val.length > 30 ? val.substring(0, 30) + '...' : val;
            } else {
                try {
                    valuePreview = JSON.stringify(val);
                    if (valuePreview && valuePreview.length > 50) valuePreview = valuePreview.substring(0, 50) + '...';
                } catch {
                    valuePreview = Object.prototype.toString.call(val);
                }
            }
            debugInfo.processedFields.push({ fieldKey: rawKey, valuePreview });
        });

        // Now process aggregated fields
        for (const [fieldKey, agg] of aggregated.entries()) {
            const hasArrayParts = Object.keys(agg.map).length > 0;
            const value = hasArrayParts ? agg.map : agg.scalar;

            if (fieldKey.startsWith('general::')) {
                const generalFieldName = fieldKey.split('::')[1];
                let matchingFields = 0;
                Object.values(values).forEach(data => {
                    if (data.field.friendly_name === generalFieldName) {
                        if (!fileUpdates[data.filePath]) fileUpdates[data.filePath] = [];
                        fileUpdates[data.filePath].push({ field: data.field, value });
                        matchingFields++;
                        debugInfo.fieldsUpdated.push({
                            file: data.filePath,
                            yamlKey: data.field.yaml_key,
                            yamlPath: data.field.yaml_path,
                            friendlyName: data.field.friendly_name,
                            newValue: hasArrayParts ? '[array]' : value,
                            source: 'general'
                        });
                    }
                });
            } else {
                const data = values[fieldKey];
                if (data) {
                    if (!fileUpdates[data.filePath]) fileUpdates[data.filePath] = [];
                    fileUpdates[data.filePath].push({ field: data.field, value });
                    debugInfo.fieldsUpdated.push({
                        file: data.filePath,
                        yamlKey: data.field.yaml_key,
                        yamlPath: data.field.yaml_path,
                        friendlyName: data.field.friendly_name,
                        newValue: hasArrayParts ? '[array]' : value,
                        source: 'specific'
                    });

                    // Sync same friendly_name to other files
                    const friendlyName = data.field.friendly_name;
                    Object.entries(values).forEach(([otherFieldKey, otherData]) => {
                        if (otherFieldKey !== fieldKey && otherData.field.friendly_name === friendlyName) {
                            if (!fileUpdates[otherData.filePath]) fileUpdates[otherData.filePath] = [];
                            fileUpdates[otherData.filePath].push({ field: otherData.field, value });
                            debugInfo.fieldsUpdated.push({
                                file: otherData.filePath,
                                yamlKey: otherData.field.yaml_key,
                                yamlPath: otherData.field.yaml_path,
                                friendlyName: otherData.field.friendly_name,
                                newValue: hasArrayParts ? '[array]' : value,
                                source: 'synced'
                            });
                        }
                    });
                } else {
                    console.log(`  ❌ Field not found in values: ${fieldKey}`);
                }
            }
        }
        
        console.log(`📊 File updates summary:`);
        Object.entries(fileUpdates).forEach(([filePath, updates]) => {
            console.log(`  📁 ${filePath}: ${updates.length} updates`);
            updates.forEach(update => {
                const pathStr = Array.isArray(update.field.yaml_path) ? update.field.yaml_path.join('.') : 'root';
                const valueStr = typeof update.value === 'object' ? JSON.stringify(update.value) : String(update.value);
                console.log(`    - ${update.field.yaml_key} (${pathStr}) = "${valueStr}"`);
            });
        });

        // Validation/guard: Prevent wiping arrays to empty when form posts nothing
        for (const [filePath, updates] of Object.entries(fileUpdates)) {
            // Load current YAML for this file once if needed
            let currentYaml = null;
            const filteredUpdates = [];
            for (const update of updates) {
                const isArrayField = update.field && typeof update.field.field_type === 'string' && update.field.field_type.startsWith('array[');
                if (isArrayField) {
                    const processed = this.processArrayValue(update.field, update.value);
                    if (!processed || processed.length === 0) {
                        if (!currentYaml) {
                            try {
                                const raw = await fs.readFile(filePath, 'utf8');
                                currentYaml = yaml.parse(raw);
                            } catch (e) {
                                currentYaml = {};
                            }
                        }
                        const existing = this.getValueFromYamlPath(currentYaml, update.field.yaml_path, update.field.yaml_key);
                        const hasExisting = Array.isArray(existing) && existing.length > 0;
                        if (hasExisting) {
                            // Skip setting this array to empty; keep current YAML as-is
                            // (including users: preserve existing users when form posts none)
                            continue;
                        } else {
                            // No existing items and processed is empty
                            if (update.field.yaml_key === 'users') {
                                throw new Error('At least one MCP user is required');
                            }
                        }
                    }
                }
                filteredUpdates.push(update);
            }
            fileUpdates[filePath] = filteredUpdates;
        }
        
        // Update each file and track which services need restart
        const servicesNeedingRestart = [];
        
        for (const [filePath, updates] of Object.entries(fileUpdates)) {
            try {
                debugInfo.filesUpdated.push(filePath);
                debugInfo.totalUpdatesApplied += updates.length;
                
                await this.updateConfigFile(filePath, updates);
                console.log(`✅ Updated config file: ${filePath} (${updates.length} changes)`);
                
                // Find the config definition for this file to get restart command
                const configFile = this.config.dashboard.configs.files.find(f => f.location === filePath);
                if (configFile && configFile.restart_command) {
                    console.log(`🔄 Service restart required: ${configFile.name} (${configFile.restart_command})`);
                    servicesNeedingRestart.push({
                        name: configFile.name,
                        filePath: filePath,
                        restartCommand: configFile.restart_command
                    });
                }
            } catch (error) {
                console.error(`❌ Error updating file ${filePath}:`, error);
                throw error;
            }
        }
        
        console.log(`🏁 Save completed: ${debugInfo.filesUpdated.length} files, ${debugInfo.totalUpdatesApplied} updates, ${servicesNeedingRestart.length} services need restart`);
        
        return { servicesNeedingRestart, ...debugInfo };
    }
    
    // Update config file with new values (object-based, safe, with backup)
    async updateConfigFile(filePath, updates) {
        console.log(`📝 Updating file: ${filePath} with ${updates.length} updates`);

        // Read and parse current YAML
        const originalText = await fs.readFile(filePath, 'utf8');
        let yamlObj;
        try {
            yamlObj = yaml.parse(originalText) || {};
        } catch (e) {
            console.error(`❌ Failed to parse YAML before update for ${filePath}:`, e);
            throw new Error(`Invalid YAML in ${filePath}; aborting update`);
        }

        // Apply updates in-memory and track if anything actually changed
        let anyChange = false;
        for (const update of updates) {
            const { field, value } = update;
            const pathStr = Array.isArray(field.yaml_path) ? field.yaml_path.join('.') : '';
            console.log(`  🔧 Updating field: ${pathStr ? pathStr + '.' : ''}${field.yaml_key}`);

            let processedValue = await this.processFieldValue(field, value);

            // Skip updating field if processedValue is null (e.g., empty password = don't change)
            if (processedValue === null && field.field_type === 'password') {
                console.log(`  ⏭️  Skipping password field with null value`);
                continue;
            }

            // Compute final value
            const finalValue = this.computeFinalValueFromField(field, processedValue);

            // Compare with current value; if equal, skip to preserve file formatting/comments
            const currentVal = this.getValueFromYamlPath(yamlObj, field.yaml_path || [], field.yaml_key);
            const isMcpServices = field.yaml_key === 'mcp_services';
            const equal = isMcpServices ? false : this.deepEqualYaml(currentVal, finalValue);
            if (equal) {
                console.log('  ⏭️  No change detected; skipping write for this field');
                continue;
            }
            const updated = this.setValueAtPath(yamlObj, field.yaml_path || [], field.yaml_key, finalValue);
            if (!updated) {
                console.warn(`  ⚠️  Skipped update: Path/key not found for ${pathStr ? pathStr + '.' : ''}${field.yaml_key}`);
            } else {
                anyChange = true;
            }
        }

        if (!anyChange) {
            console.log('ℹ️ No actual changes detected; file will not be rewritten');
            return;
        }

        // Backup original file
        const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
        const backupPath = `${filePath}.bak.${ts}`;
        await fs.writeFile(backupPath, originalText, 'utf8');

        // Serialize and write
        const newText = yaml.stringify(yamlObj);
        await fs.writeFile(filePath, newText, 'utf8');

        // Validate written YAML by parsing again
        try {
            yaml.parse(await fs.readFile(filePath, 'utf8'));
        } catch (e) {
            console.error(`❌ YAML validation failed after write for ${filePath}, restoring backup:`, e);
            await fs.writeFile(filePath, originalText, 'utf8');
            throw new Error(`Failed to write valid YAML to ${filePath}; restored previous version`);
        }

        console.log(`✅ File written successfully: ${filePath}`);
    }

    // Helper: produce final persisted value
    computeFinalValueFromField(field, processedValue) {
        if (field.field_type && field.field_type.startsWith('array[')) {
            return processedValue;
        }
        if (field.field_type === 'multiline') {
            return typeof processedValue === 'string' ? processedValue : String(processedValue ?? '');
        }
        let asString = typeof processedValue === 'object' ? JSON.stringify(processedValue) : String(processedValue ?? '');
        if (field.prepend) asString = field.prepend + asString;
        if (field.append) asString = asString + field.append;
        return asString;
    }

    // Helper: shallow/deep compare for YAML values (arrays/objects/strings/numbers)
    deepEqualYaml(a, b) {
        if (a === b) return true;
        if (typeof a !== typeof b) return false;
        if (a && b && typeof a === 'object') {
            try {
                return JSON.stringify(a) === JSON.stringify(b);
            } catch {
                return false;
            }
        }
        return false;
    }

    // Helper: Set value at yaml_path + key safely; returns true if updated
    setValueAtPath(obj, pathArr, key, value) {
        let current = obj;
        for (const segment of pathArr) {
            if (!current || typeof current !== 'object' || !(segment in current)) {
                return false; // Do not create missing paths; skip update
            }
            current = current[segment];
        }
        if (!current || typeof current !== 'object' || !(key in current)) {
            return false; // Only update existing editable fields
        }
        current[key] = value;
        return true;
    }
    
    // Process field value based on field type
    async processFieldValue(field, value) {
        switch (field.field_type) {
            case 'password':
                if (value && value.trim() !== '') {
                    return await bcrypt.hash(value, 10);
                }
                // Return null for empty passwords - this means "don't change existing password"
                return null;
                
            case 'hash':
                if (!value || value.trim() === '') {
                    const length = field.length || 32;
                    return crypto.randomBytes(length).toString('base64').slice(0, length);
                }
                return value;
                
            default:
                if (field.field_type && field.field_type.startsWith('array[')) {
                    return this.processArrayValue(field, value);
                }
                return value;
        }
    }
    
    // Process array field values
    processArrayValue(field, value) {
        console.log(`🔍 [DEBUG] processArrayValue called for field:`, field.yaml_key);
        console.log(`🔍 [DEBUG] Input value type:`, typeof value);
        console.log(`🔍 [DEBUG] Input value:`, typeof value === 'object' ? JSON.stringify(value, null, 2) : value);
        if (!value) return [];
        
        const arrayType = field.field_type.match(/array\[(.+)\]/)[1];
        const result = [];
        
        if (arrayType.includes(':')) {
            // Complex array with subtypes
            const subTypes = arrayType.split(',').map(type => {
                const parts = type.split(':');
                return { type: parts[0], name: parts[1] || parts[0] };
            });
            
            // Group form data by array index; support nested array subfields, e.g. [0][options][1]
            const itemsByIndex = {};
            Object.entries(value).forEach(([key, val]) => {
                const match = key.match(/^\[(\d+)\]\[([^\]]+)\](?:\[(\d+)\])?$/);
                if (!match) return;
                const index = parseInt(match[1]);
                const subField = match[2];
                const innerIdx = match[3];
                if (!itemsByIndex[index]) itemsByIndex[index] = {};
                if (innerIdx !== undefined) {
                    if (!itemsByIndex[index][subField]) itemsByIndex[index][subField] = [];
                    if (typeof val === 'string' && val.trim() !== '') {
                        itemsByIndex[index][subField].push(val);
                    }
                } else {
                    if (val !== undefined && String(val).trim() !== '') {
                        itemsByIndex[index][subField] = val;
                    }
                }
            });
            
            // Process each complex array item
            Object.keys(itemsByIndex).sort((a,b)=>Number(a)-Number(b)).forEach(idx => {
                const item = itemsByIndex[idx];
                const obj = {};
                subTypes.forEach(subType => {
                    const key = subType.name;
                    const val = item[key];
                    if (subType.type && subType.type.startsWith('array[')) {
                        if (Array.isArray(val)) {
                            obj[key] = val;
                        }
                    } else if (val !== undefined && val !== '') {
                        obj[key] = val;
                    }
                });
                if (Object.keys(obj).length > 0) result.push(obj);
            });
        } else {
            // Simple array
            Object.entries(value).forEach(([key, val]) => {
                const match = key.match(/\[(\d+)\]$/);
                if (match && val && val.trim() !== '') {
                    result.push(val.trim());
                }
            });
        }
        
        return result;
    }
    
    // Format array value for YAML output
    formatArrayValue(arrayValue, field, indent) {
        const lines = [];
        
        const arrayType = field.field_type.match(/array\[(.+)\]/)[1];
        const subTypes = arrayType.split(',').map(type => {
            const parts = type.split(':');
            return { type: parts[0], name: parts[1] || parts[0] };
        });
        
        arrayValue.forEach(item => {
            if (subTypes.length === 1) {
                // Simple array
                lines.push(`${indent}- ${item}`);
            } else {
                // Complex array (object)
                lines.push(`${indent}- ${subTypes[0].name}: ${item[subTypes[0].name] || ''}`);
                subTypes.slice(1).forEach(subType => {
                    const value = item[subType.name];
                    if (value !== undefined) {
                        if (subType.type === 'multiline' && value.includes('\n')) {
                            lines.push(`${indent}  ${subType.name}: |`);
                            value.split('\n').forEach(line => {
                                lines.push(`${indent}    ${line}`);
                            });
                        } else {
                            const valueStr = typeof value === 'object' ? JSON.stringify(value) : String(value);
                            lines.push(`${indent}  ${subType.name}: ${valueStr}`);
                        }
                    }
                });
            }
        });
        
        return lines;
    }
    
    // Generate random hash
    generateRandomHash(length = 32) {
        return crypto.randomBytes(length).toString('base64').slice(0, length);
    }
    
    // API endpoint to generate hash
    setupHashGenerationRoute() {
        this.router.post('/api/generate-hash', this.requireAuth.bind(this), (req, res) => {
            const { length } = req.body;
            const hash = this.generateRandomHash(length || 32);
            res.json({ hash });
        });
    }
    
    // User management routes
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
                const { serviceName, restartCommand } = req.body;
                
                if (!serviceName || !restartCommand) {
                    return res.status(400).json({ error: 'Service name and restart command are required' });
                }
                
                console.log(`🔄 Restarting service: ${serviceName} with command: ${restartCommand}`);
                
                // Special handling for MCP Server configuration restart - warn about dashboard restart
                const isDashboardRestart = serviceName === 'MCP Server configuration';
                
                try {
                    const { stdout, stderr } = await execAsync(restartCommand);
                    console.log(`✅ Service restart completed for ${serviceName}`);
                    if (stdout) console.log('Restart stdout:', stdout);
                    if (stderr) console.log('Restart stderr:', stderr);
                    
                    res.json({ 
                        success: true, 
                        message: `${serviceName} restarted successfully`,
                        isDashboardRestart
                    });
                } catch (execError) {
                    console.error(`❌ Service restart failed for ${serviceName}:`, execError);
                    res.status(500).json({ 
                        error: `Failed to restart ${serviceName}: ${execError.message}`,
                        isDashboardRestart
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

        // List all services from dashboard.yaml that have a restart_command
        this.router.get('/api/services-with-restart', this.requireAuth.bind(this), async (req, res) => {
            try {
                // Always reload dashboard config to reflect latest changes
                await this.loadDashboardConfig();

                const files = (this.config?.dashboard?.configs?.files || []);
                const services = files
                    .filter(f => !!f.restart_command && !!f.name)
                    .map(f => ({ name: f.name, restartCommand: f.restart_command }))
                    // Ensure dashboard/server restart goes last to avoid interrupting others
                    .sort((a, b) => {
                        const isDashA = a.name === 'MCP Server configuration';
                        const isDashB = b.name === 'MCP Server configuration';
                        return (isDashA === isDashB) ? 0 : (isDashA ? 1 : -1);
                    });

                res.json({ services });
            } catch (error) {
                console.error('Error listing services with restart:', error);
                res.status(500).json({ error: 'Failed to list services' });
            }
        });
    }

    // Preview config changes without writing to disk
    setupPreviewRoute() {
        this.router.post('/api/preview-config', this.requireAuth.bind(this), async (req, res) => {
            try {
                const values = await this.loadCurrentValues();

                // Build fileUpdates similar to saveConfiguration
                const fileUpdates = {};
                Object.entries(req.body).forEach(([fieldKey, value]) => {
                    if (fieldKey.startsWith('general::')) {
                        const generalFieldName = fieldKey.split('::')[1];
                        Object.values(values).forEach(data => {
                            if (data.field.friendly_name === generalFieldName) {
                                if (!fileUpdates[data.filePath]) fileUpdates[data.filePath] = [];
                                fileUpdates[data.filePath].push({ field: data.field, value });
                            }
                        });
                    } else {
                        const data = values[fieldKey];
                        if (data) {
                            if (!fileUpdates[data.filePath]) fileUpdates[data.filePath] = [];
                            fileUpdates[data.filePath].push({ field: data.field, value });
                            // sync to other same friendly_name fields
                            const friendlyName = data.field.friendly_name;
                            Object.entries(values).forEach(([otherKey, otherData]) => {
                                if (otherKey !== fieldKey && otherData.field.friendly_name === friendlyName) {
                                    if (!fileUpdates[otherData.filePath]) fileUpdates[otherData.filePath] = [];
                                    fileUpdates[otherData.filePath].push({ field: otherData.field, value });
                                }
                            });
                        }
                    }
                });

                // Build preview payload per file
                const files = [];
                for (const [filePath, updates] of Object.entries(fileUpdates)) {
                    const originalText = await fs.readFile(filePath, 'utf8');
                    let yamlObj;
                    try {
                        yamlObj = yaml.parse(originalText) || {};
                    } catch (e) {
                        return res.status(400).json({ error: `Invalid YAML in ${filePath}: ${e.message}` });
                    }

                    const changes = [];
                    for (const update of updates) {
                        const processedValue = await this.processFieldValue(update.field, update.value);
                        if (processedValue === null && update.field.field_type === 'password') continue;
                        const finalValue = this.computeFinalValueFromField(update.field, processedValue);
                        const currentVal = this.getValueFromYamlPath(yamlObj, update.field.yaml_path || [], update.field.yaml_key);
                        if (!this.deepEqualYaml(currentVal, finalValue)) {
                            changes.push({
                                path: `${(update.field.yaml_path || []).join('.')}.${update.field.yaml_key}`.replace(/^\./, ''),
                                before: currentVal,
                                after: finalValue
                            });
                            // Apply to a copy so newText reflects the change for this preview
                            this.setValueAtPath(yamlObj, update.field.yaml_path || [], update.field.yaml_key, finalValue);
                        }
                    }

                    const newText = yaml.stringify(yamlObj);
                    files.push({ filePath, changes, originalText, newText });
                }

                res.json({ files });
            } catch (error) {
                console.error('Error building preview:', error);
                res.status(500).json({ error: 'Failed to build preview' });
            }
        });
    }

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

    // Sanitize regex for HTML pattern attribute across modern browsers (escape '-' in char classes)
    sanitizeHtmlPattern(pattern) {
        try {
            // Replace hyphen inside character classes with escaped version to avoid 'v' flag issues
            return pattern.replace(/\[(?:\\.|[^\]\\])*\]/g, (cls) => cls.replace(/-/g, '\\-'));
        } catch (e) {
            return pattern; // Fallback to original if something goes wrong
        }
    }
    
    // Find the line number for a field considering its YAML path context
    findFieldLineWithPath(lines, field) {
        // Add safety checks
        if (!field || !field.yaml_key) {
            console.warn('findFieldLineWithPath: Invalid field object', field);
            return -1;
        }
        
        const { yaml_path, yaml_key } = field;
        
        // Escape regex special characters in yaml_key
        const escapedKey = yaml_key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        
        // If no path, use simple search
        if (!yaml_path || yaml_path.length === 0) {
            for (let i = 0; i < lines.length; i++) {
                if (lines[i] && lines[i].match(new RegExp(`^\\s*${escapedKey}:\\s*`))) {
                    return i;
                }
            }
            return -1;
        }
        
        // Navigate through the YAML path to find the correct context
        let currentIndentLevel = 0;
        let pathIndex = 0;
        
        for (let i = 0; i < lines.length; i++) {
            if (!lines[i]) continue;
            
            const line = lines[i].trim();
            
            // Skip empty lines and comments
            if (line === '' || line.startsWith('#')) {
                continue;
            }
            
            const lineIndent = lines[i].search(/\S/);
            
            // If we've completed the path, look for our target key at the correct indent
            if (pathIndex >= yaml_path.length) {
                const expectedIndent = currentIndentLevel + 2; // YAML typically uses 2-space indentation
                if (lineIndent === expectedIndent && line.startsWith(yaml_key + ':')) {
                    return i;
                }
                // If we've moved to a different section, reset
                if (lineIndent <= currentIndentLevel) {
                    pathIndex = 0;
                    currentIndentLevel = 0;
                }
                continue;
            }
            
            // Check if this line matches the current path segment
            const currentPathSegment = yaml_path[pathIndex];
            if (currentPathSegment && line.startsWith(currentPathSegment + ':')) {
                // If this is at the expected indent level
                if (lineIndent === currentIndentLevel) {
                    pathIndex++;
                    currentIndentLevel = lineIndent;
                    
                    // If we've completed the path, the next target should be at the next indent level
                    if (pathIndex >= yaml_path.length) {
                        currentIndentLevel += 2;
                    }
                }
            }
            // If we encounter a line at the same or less indentation, reset if we haven't found our path
            else if (lineIndent <= currentIndentLevel && pathIndex < yaml_path.length) {
                pathIndex = 0;
                currentIndentLevel = 0;
                
                // Check if this line might be the start of our path
                if (yaml_path.length > 0 && line.startsWith(yaml_path[0] + ':')) {
                    pathIndex = 1;
                    currentIndentLevel = lineIndent;
                }
            }
        }
        
        return -1;
    }
    
    async shutdown() {
        console.log('Dashboard Service shutting down...');
        // No cleanup needed for dashboard service
    }
}
