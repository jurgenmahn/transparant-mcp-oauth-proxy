import express from 'express';
import bcrypt from 'bcrypt';
import fs from 'fs/promises';
import path from 'path';
import yaml from 'yaml';

export class DashboardService {
    constructor(appPath) {
        this.appPath = appPath;
        this.router = express.Router();
        this.config = {};
        this.setupRoutes();
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
    
    // Parse placeholder format: << data-type::name::validation::allowed-values >>
    parsePlaceholder(placeholder) {
        const match = placeholder.match(/<<\s*(.+?)\s*>>/);
        if (!match) return null;
        
        const parts = match[1].split('::');
        if (parts.length < 2) return null;
        
        return {
            original: placeholder,
            dataType: parts[0],
            name: parts[1],
            validation: parts[2] || null,
            allowedValues: parts[3] || null
        };
    }
    
    // Extract placeholders from config files
    async extractPlaceholders(filePath) {
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const placeholderRegex = /<<[^>]+>>/g;
            const matches = content.match(placeholderRegex) || [];
            
            return matches.map(match => {
                const parsed = this.parsePlaceholder(match);
                if (parsed) {
                    parsed.lineContext = this.getLineContext(content, match);
                }
                return parsed;
            }).filter(Boolean);
        } catch (error) {
            console.error(`Error reading file ${filePath}:`, error);
            return [];
        }
    }
    
    // Get surrounding context for a placeholder
    getLineContext(content, placeholder) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes(placeholder)) {
                return {
                    lineNumber: i + 1,
                    line: lines[i].trim(),
                    yamlPath: this.extractYamlPath(lines, i)
                };
            }
        }
        return null;
    }
    
    // Extract YAML path from line context
    extractYamlPath(lines, lineIndex) {
        const path = [];
        let currentIndent = -1;
        
        for (let i = lineIndex; i >= 0; i--) {
            const line = lines[i];
            if (line.trim() === '') continue;
            
            const indent = line.search(/\S/);
            const match = line.match(/^\s*([^:]+):/);
            
            if (match && (currentIndent === -1 || indent < currentIndent)) {
                path.unshift(match[1].trim());
                currentIndent = indent;
            }
        }
        
        return path.join('.');
    }
    
    // Load current values from destination files
    async loadCurrentValues() {
        const values = {};
        
        for (const file of this.config.dashboard.configs.files) {
            const sourcePath = path.join(this.config.dashboard.configs['source-base-path'], file.location);
            const destPath = path.join(this.config.dashboard.configs['destination-base-path'], file.location);
            
            try {
                // First try to load from destination
                let content = '';
                try {
                    content = await fs.readFile(destPath, 'utf8');
                } catch {
                    // Fallback to source
                    content = await fs.readFile(sourcePath, 'utf8');
                }
                
                const placeholders = await this.extractPlaceholders(sourcePath);
                
                for (const placeholder of placeholders) {
                    const currentValue = this.extractCurrentValue(content, placeholder);
                    const fieldKey = `${file.name}::${placeholder.name}`;
                    values[fieldKey] = {
                        file: file.name,
                        placeholder: placeholder,
                        currentValue: currentValue
                    };
                }
            } catch (error) {
                console.error(`Error processing file ${file.name}:`, error);
            }
        }
        
        return values;
    }
    
    // Extract current value from destination file
    extractCurrentValue(content, placeholder) {
        if (!placeholder.lineContext) return null;
        
        const lines = content.split('\n');
        const targetLine = lines.find(line => 
            line.includes(placeholder.lineContext.yamlPath) || 
            line.includes(placeholder.name.toLowerCase())
        );
        
        if (!targetLine) return null;
        
        // Extract value based on data type
        switch (placeholder.dataType) {
            case 'string':
                const stringMatch = targetLine.match(/:\s*(.+)$/);
                return stringMatch ? stringMatch[1].trim() : null;
            
            case 'array':
                // Look for array items in following lines
                const arrayValues = [];
                const startIndex = lines.indexOf(targetLine);
                if (startIndex !== -1) {
                    for (let i = startIndex + 1; i < lines.length; i++) {
                        const line = lines[i];
                        if (line.match(/^\s*-\s+/)) {
                            arrayValues.push(line.replace(/^\s*-\s+/, '').trim());
                        } else if (line.match(/^\s*\w+:/)) {
                            break;
                        }
                    }
                }
                return arrayValues;
            
            case 'object-array':
                // Complex object array parsing would go here
                return [];
            
            default:
                return null;
        }
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
            const fieldName = data.placeholder.name;
            fieldCounts[fieldName] = (fieldCounts[fieldName] || 0) + 1;
        });
        
        const generalFields = Object.keys(fieldCounts).filter(name => fieldCounts[name] > 1);
        
        // Generate general section for common fields
        if (generalFields.length > 0) {
            formHtml += `
                <div class="section general-section">
                    <div class="section-header">General Settings</div>
                    <div class="section-content">
            `;
            
            generalFields.forEach(fieldName => {
                const firstData = Object.values(values).find(data => data.placeholder.name === fieldName);
                formHtml += this.generateFieldHtml(`general::${fieldName}`, firstData);
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
                if (!generalFields.includes(data.placeholder.name)) {
                    const fieldKey = `${fileName}::${data.placeholder.name}`;
                    formHtml += this.generateFieldHtml(fieldKey, data);
                }
            });
            
            formHtml += '</div></div>';
        });
        
        return formHtml;
    }
    
    // Generate HTML for individual field
    generateFieldHtml(fieldKey, data) {
        const { placeholder, currentValue } = data;
        let fieldHtml = `<div class="field-group">`;
        
        fieldHtml += `<label for="${fieldKey}">${placeholder.name}</label>`;
        
        if (placeholder.allowedValues && placeholder.allowedValues !== 'null') {
            // Multi-select for allowed values
            const options = placeholder.allowedValues.replace(/"/g, '').split(';');
            fieldHtml += `<select name="${fieldKey}" id="${fieldKey}">`;
            options.forEach(option => {
                const selected = currentValue === option ? 'selected' : '';
                fieldHtml += `<option value="${option}" ${selected}>${option}</option>`;
            });
            fieldHtml += '</select>';
        } else {
            switch (placeholder.dataType) {
                case 'string':
                    const value = currentValue || '';
                    fieldHtml += `<input type="text" name="${fieldKey}" id="${fieldKey}" value="${value}"`;
                    if (placeholder.validation && placeholder.validation !== 'null') {
                        fieldHtml += ` pattern="${placeholder.validation}"`;
                    }
                    fieldHtml += '>';
                    break;
                    
                case 'number':
                    fieldHtml += `<input type="number" name="${fieldKey}" id="${fieldKey}" value="${currentValue || ''}"`;
                    if (placeholder.validation && placeholder.validation !== 'null') {
                        fieldHtml += ` pattern="${placeholder.validation}"`;
                    }
                    fieldHtml += '>';
                    break;
                    
                case 'bcrypt':
                    fieldHtml += `<input type="password" name="${fieldKey}" id="${fieldKey}" placeholder="Enter new password">`;
                    break;
                    
                case 'array':
                    fieldHtml += `<div id="${fieldKey}_container">`;
                    if (Array.isArray(currentValue)) {
                        currentValue.forEach(val => {
                            fieldHtml += `<input type="text" name="${fieldKey}[]" class="array-input" value="${val}">`;
                        });
                    }
                    fieldHtml += `</div>`;
                    fieldHtml += `<button type="button" class="add-array-item" onclick="addArrayItem('${fieldKey}')">Add Item</button>`;
                    break;
                    
                case 'object-array':
                    fieldHtml += `<textarea name="${fieldKey}" id="${fieldKey}" placeholder="Enter YAML format">${JSON.stringify(currentValue || [], null, 2)}</textarea>`;
                    break;
                    
                default:
                    fieldHtml += `<input type="text" name="${fieldKey}" id="${fieldKey}" value="${currentValue || ''}">`;
            }
        }
        
        fieldHtml += '</div>';
        return fieldHtml;
    }
    
    // Save configuration files
    async saveConfiguration(formData) {
        const values = await this.loadCurrentValues();
        
        // Process form data and update files
        for (const file of this.config.dashboard.configs.files) {
            const sourcePath = path.join(this.config.dashboard.configs['source-base-path'], file.location);
            const destPath = path.join(this.config.dashboard.configs['destination-base-path'], file.location);
            
            try {
                let content = await fs.readFile(sourcePath, 'utf8');
                
                // Replace placeholders with form values
                Object.entries(formData).forEach(([fieldKey, value]) => {
                    if (fieldKey.startsWith(`${file.name}::`) || fieldKey.startsWith('general::')) {
                        const fieldName = fieldKey.split('::')[1];
                        const placeholder = Object.values(values).find(v => 
                            v.placeholder.name === fieldName && (
                                v.file === file.name || fieldKey.startsWith('general::')
                            )
                        );
                        
                        if (placeholder) {
                            content = this.replacePlaceholderWithValue(content, placeholder.placeholder, value);
                        }
                    }
                });
                
                // Ensure destination directory exists
                await fs.mkdir(path.dirname(destPath), { recursive: true });
                
                // Write updated content to destination
                await fs.writeFile(destPath, content, 'utf8');
                console.log(`Updated ${file.name}: ${destPath}`);
                
            } catch (error) {
                console.error(`Error updating file ${file.name}:`, error);
                throw error;
            }
        }
    }
    
    // Replace placeholder with actual value
    async replacePlaceholderWithValue(content, placeholder, value) {
        let processedValue = value;
        
        // Process value based on data type
        switch (placeholder.dataType) {
            case 'bcrypt':
                if (value && value.trim() !== '') {
                    processedValue = await bcrypt.hash(value, 10);
                } else {
                    return content; // Don't replace if password is empty
                }
                break;
                
            case 'array':
                if (Array.isArray(value)) {
                    processedValue = value.filter(v => v.trim() !== '');
                } else {
                    processedValue = [];
                }
                break;
                
            case 'object-array':
                try {
                    processedValue = typeof value === 'string' ? JSON.parse(value) : value;
                } catch {
                    processedValue = [];
                }
                break;
                
            case 'number':
                processedValue = parseFloat(value) || 0;
                break;
                
            default:
                processedValue = value;
        }
        
        // Replace placeholder in content
        if (placeholder.dataType === 'array') {
            // Handle array replacement with proper YAML formatting
            const arrayYaml = processedValue.map(item => `    - ${item}`).join('\n');
            const replacement = `\n${arrayYaml}`;
            return content.replace(placeholder.original, replacement);
        } else if (placeholder.dataType === 'object-array') {
            // Handle object array with YAML formatting
            const objectYaml = yaml.stringify(processedValue).split('\n').map(line => `  ${line}`).join('\n');
            return content.replace(placeholder.original, `\n${objectYaml}`);
        } else {
            return content.replace(placeholder.original, processedValue);
        }
    }
    
    getRouter() {
        return this.router;
    }
    
    async shutdown() {
        console.log('Dashboard Service shutting down...');
        // No cleanup needed for dashboard service
    }
}