import express from 'express';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import yaml from 'yaml';

export class DashboardService {
    constructor(appPath) {
        this.appPath = appPath;
        this.router = express.Router();
        this.config = {};
        this.setupRoutes();
        this.setupHashGenerationRoute();
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
                const formContent = this.generateFormContent(values);
                const templatePath = path.join(process.cwd(), 'templates', 'dashboard.html');
                let html = await fs.readFile(templatePath, 'utf8');
                html = html.replace('{{FORM_CONTENT}}', formContent);
                res.send(html);
            } catch (error) {
                console.error('Error generating dashboard:', error);
                res.status(500).send('Error loading configuration dashboard');
            }
        });
        
        // Login endpoint
        this.router.post('/login', async (req, res) => {
            try {
                await this.authenticate(req, res, () => {
                    res.json({ success: true, message: 'Authentication successful' });
                });
            } catch (error) {
                res.status(401).json({ success: false, error: error.message });
            }
        });
        
        // Save configuration
        this.router.post('/save-config', async (req, res) => {
            try {
                await this.authenticate(req, res, async () => {
                    await this.saveConfiguration(req.body);
                    res.json({ success: true, message: 'Configuration saved successfully' });
                });
            } catch (error) {
                console.error('Error saving configuration:', error);
                res.status(500).json({ success: false, error: 'Failed to save configuration' });
            }
        });
        
        // Get current configuration (API endpoint)
        this.router.get('/api/config', async (req, res) => {
            try {
                const values = await this.loadCurrentValues();
                res.json(values);
            } catch (error) {
                console.error('Error loading config values:', error);
                res.status(500).json({ error: 'Failed to load configuration' });
            }
        });
        
        // Debug endpoint to see extracted fields
        this.router.get('/api/debug', async (req, res) => {
            try {
                const fields = await this.extractFieldDefinitions('/home/jurgen/sites/create_all_containers/mcp-launcher/app/config/local.yaml');
                res.json({ fields, count: fields.length });
            } catch (error) {
                console.error('Error in debug:', error);
                res.status(500).json({ error: error.message });
            }
        });
    }
    
    // Authentication middleware
    async authenticate(req, res, next) {
        const { email, password } = req.body;
        
        if (!email || !password) {
            throw new Error('Email and password required');
        }
        
        const user = this.config.dashboard.users.find(u => u.email === email);
        if (!user) {
            throw new Error('Invalid credentials');
        }
        
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            throw new Error('Invalid credentials');
        }
        
        await next();
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
            }
        }
        
        return field;
    }
    
    // Extract comment-based field definitions from config files
    async extractFieldDefinitions(filePath) {
        try {
            const content = await fs.readFile(filePath, 'utf8');
            
            // Parse the entire file as YAML first to get the actual values
            const yamlData = yaml.parse(content);
            
            // Now extract the fields using a simple approach
            const fields = [];
            const dashboardBlocks = this.findDashboardBlocks(content);
            
            for (const block of dashboardBlocks) {
                const field = this.parseFieldFromBlock(block, yamlData);
                if (field) {
                    fields.push(field);
                }
            }
            
            return fields;
        } catch (error) {
            console.error(`Error reading file ${filePath}:`, error);
            return [];
        }
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
                
                // Collect comment lines
                let j = i + 1;
                while (j < lines.length && lines[j].trim().startsWith('#')) {
                    const comment = lines[j].replace(/^#\s*/, '').trim();
                    if (comment) {
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
        // Remove any remaining # prefixes
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
            if (values !== 'null') {
                field.allowed_values = values.split(',').map(v => v.trim());
            }
        } else if (trimmed.startsWith('validation:')) {
            const validation = trimmed.substring('validation:'.length).trim();
            if (validation !== 'null') {
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
        }
    }
    
    // Build YAML path for a line
    buildYamlPath(lines, lineIndex) {
        const path = [];
        const currentIndent = lines[lineIndex].search(/\S/);
        
        for (let i = lineIndex - 1; i >= 0; i--) {
            const line = lines[i];
            if (line.trim() === '' || line.trim().startsWith('#')) continue;
            
            const indent = line.search(/\S/);
            if (indent < currentIndent) {
                const match = line.match(/^\s*([^:]+):/);
                if (match) {
                    path.unshift(match[1].trim());
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
                    // Use friendly_name for identification if available, otherwise use yaml_key
                    const fieldIdentifier = field.friendly_name || field.yaml_key;
                    const uniqueKey = `${file.name}::${fieldIdentifier}`;
                    
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
                    if (field.validation) fieldHtml += ` pattern="${field.validation}"`;
                    if (field.mandatory) fieldHtml += ' required';
                    fieldHtml += '>';
                    break;
                    
                case 'password':
                    fieldHtml += `<input type="password" name="${fieldKey}" id="${fieldKey}" placeholder="Enter new password"`;
                    if (field.mandatory) fieldHtml += ' required';
                    fieldHtml += '>';
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
                    if (field.validation) fieldHtml += ` pattern="${field.validation}"`;
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
                case 'multiline':
                    html += `<textarea name="${fieldKey}[${index}]" rows="3" placeholder="Enter value">${value || ''}</textarea>`;
                    break;
                default:
                    html += `<input type="text" name="${fieldKey}[${index}]" value="${value || ''}" placeholder="Enter value">`;
            }
            
            if (index > 0 || values.length > 1) {
                html += `<button type="button" class="remove-array-item" onclick="removeArrayItem(this)">Remove</button>`;
            }
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
                subValue = item[subType.name] || '';
            } else if (subIndex === 0 && typeof item === 'string') {
                // For first field, if item is a string, use it directly
                subValue = item;
            }
            
            html += `<div class="sub-field">`;
            html += `<label>${subFieldName}</label>`;
            
            switch (subType.type) {
                case 'textbox':
                    html += `<input type="text" name="${subFieldKey}" value="${subValue}"`;
                    if (field.sub_fields && field.sub_fields[subIndex] && field.sub_fields[subIndex].validation) {
                        html += ` pattern="${field.sub_fields[subIndex].validation}"`;
                    }
                    if (field.sub_fields && field.sub_fields[subIndex] && field.sub_fields[subIndex].mandatory) {
                        html += ' required';
                    }
                    html += '>';
                    break;
                    
                case 'password':
                    html += `<input type="password" name="${subFieldKey}" placeholder="Enter password"`;
                    if (field.sub_fields && field.sub_fields[subIndex] && field.sub_fields[subIndex].mandatory) {
                        html += ' required';
                    }
                    html += '>';
                    break;
                    
                case 'multiline':
                    html += `<textarea name="${subFieldKey}" rows="3">${subValue}</textarea>`;
                    break;
                    
                default:
                    html += `<input type="text" name="${subFieldKey}" value="${subValue}">`;
            }
            
            html += `</div>`;
        });
        
        if (index > 0) {
            html += `<button type="button" class="remove-array-item" onclick="removeArrayItem(this)">Remove</button>`;
        }
        html += `</div>`;
        
        return html;
    }
    
    // Save configuration files
    async saveConfiguration(formData) {
        const values = await this.loadCurrentValues();
        
        // Group form data by file
        const fileUpdates = {};
        
        Object.entries(formData).forEach(([fieldKey, value]) => {
            if (fieldKey.startsWith('general::')) {
                // Apply general fields to all files that have them
                const generalFieldName = fieldKey.split('::')[1];
                Object.values(values).forEach(data => {
                    if (data.field.friendly_name === generalFieldName) {
                        if (!fileUpdates[data.filePath]) fileUpdates[data.filePath] = [];
                        fileUpdates[data.filePath].push({ field: data.field, value });
                    }
                });
            } else {
                // File-specific field
                const data = values[fieldKey];
                if (data) {
                    if (!fileUpdates[data.filePath]) fileUpdates[data.filePath] = [];
                    fileUpdates[data.filePath].push({ field: data.field, value });
                }
            }
        });
        
        // Update each file
        for (const [filePath, updates] of Object.entries(fileUpdates)) {
            try {
                await this.updateConfigFile(filePath, updates);
                console.log(`Updated config file: ${filePath}`);
            } catch (error) {
                console.error(`Error updating file ${filePath}:`, error);
                throw error;
            }
        }
    }
    
    // Update config file with new values
    async updateConfigFile(filePath, updates) {
        const content = await fs.readFile(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (const update of updates) {
            const { field, value } = update;
            let processedValue = await this.processFieldValue(field, value);
            
            // Find the line with this field
            const fieldPattern = new RegExp(`^(\\s*)${field.yaml_key}:\\s*(.*)$`);
            
            for (let i = 0; i < lines.length; i++) {
                const match = lines[i].match(fieldPattern);
                if (match) {
                    const indent = match[1];
                    
                    if (field.field_type && field.field_type.startsWith('array[')) {
                        // Handle array fields
                        lines[i] = `${indent}${field.yaml_key}:`;
                        
                        // Remove existing array items
                        let j = i + 1;
                        while (j < lines.length && 
                               (lines[j].trim() === '' || 
                                lines[j].trim().startsWith('#') || 
                                lines[j].match(/^\s*-\s/) ||
                                (lines[j].match(/^\s+\w+:/) && lines[j].search(/\S/) > indent.length))) {
                            lines.splice(j, 1);
                        }
                        
                        // Add new array items
                        if (Array.isArray(processedValue)) {
                            const arrayLines = this.formatArrayValue(processedValue, field, indent + '  ');
                            lines.splice(i + 1, 0, ...arrayLines);
                        }
                    } else if (field.field_type === 'multiline') {
                        // Handle multiline fields
                        lines[i] = `${indent}${field.yaml_key}: |`;
                        
                        // Remove existing multiline content
                        let j = i + 1;
                        while (j < lines.length && lines[j].search(/\S/) > indent.length) {
                            lines.splice(j, 1);
                        }
                        
                        // Add new multiline content
                        if (processedValue) {
                            const multilineLines = processedValue.split('\n').map(line => `${indent}  ${line}`);
                            lines.splice(i + 1, 0, ...multilineLines);
                        }
                    } else {
                        // Handle simple fields
                        let finalValue = processedValue;
                        if (field.prepend) finalValue = field.prepend + finalValue;
                        if (field.append) finalValue = finalValue + field.append;
                        lines[i] = `${indent}${field.yaml_key}: ${finalValue}`;
                    }
                    break;
                }
            }
        }
        
        // Write updated content back to file
        await fs.writeFile(filePath, lines.join('\n'), 'utf8');
    }
    
    // Process field value based on field type
    async processFieldValue(field, value) {
        switch (field.field_type) {
            case 'password':
                if (value && value.trim() !== '') {
                    return await bcrypt.hash(value, 10);
                }
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
        if (!value) return [];
        
        const arrayType = field.field_type.match(/array\[(.+)\]/)[1];
        const result = [];
        
        if (arrayType.includes(':')) {
            // Complex array with subtypes
            const subTypes = arrayType.split(',').map(type => {
                const parts = type.split(':');
                return { type: parts[0], name: parts[1] || parts[0] };
            });
            
            // Group form data by array index
            const itemsByIndex = {};
            Object.entries(value).forEach(([key, val]) => {
                const match = key.match(/\[(\d+)\]\[(.+)\]$/);
                if (match) {
                    const index = parseInt(match[1]);
                    const subField = match[2];
                    if (!itemsByIndex[index]) itemsByIndex[index] = {};
                    itemsByIndex[index][subField] = val;
                }
            });
            
            // Process each complex array item
            Object.values(itemsByIndex).forEach(item => {
                const obj = {};
                subTypes.forEach(subType => {
                    const val = item[subType.name];
                    if (val !== undefined && val !== '') {
                        obj[subType.name] = val;
                    }
                });
                if (Object.keys(obj).length > 0) {
                    result.push(obj);
                }
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
                            lines.push(`${indent}  ${subType.name}: ${value}`);
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
        this.router.post('/api/generate-hash', (req, res) => {
            const { length } = req.body;
            const hash = this.generateRandomHash(length || 32);
            res.json({ hash });
        });
    }
    
    getRouter() {
        return this.router;
    }
    
    async shutdown() {
        console.log('Dashboard Service shutting down...');
        // No cleanup needed for dashboard service
    }
}