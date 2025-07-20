#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

// Hardcoded etcd settings
const ETCD_ENDPOINT = "http://127.0.0.1:2379";
const ETCD_PREFIX = "/apisix";

function decodeEtcdExport(rawJson) {
    const result = {};
    for (const item of rawJson.kvs) {
        const key = Buffer.from(item.key, 'base64').toString();
        const val = Buffer.from(item.value, 'base64').toString();
        result[key] = val.trim().startsWith('{') ? JSON.parse(val) : val;
    }
    return result;
}

function* encodeEtcdImport(data) {
    for (const [key, val] of Object.entries(data)) {
        const encodedKey = Buffer.from(key).toString('base64');
        const encodedVal = Buffer.from(
            typeof val === 'object' ? JSON.stringify(val) : String(val)
        ).toString('base64');
        yield [encodedKey, encodedVal];
    }
}

function etcdGetAll() {
    const cmd = [
        'etcdctl',
        '--endpoints', ETCD_ENDPOINT,
        'get', ETCD_PREFIX, '--prefix', '-w', 'json'
    ].join(' ');
    
    const result = execSync(cmd, { encoding: 'utf8' });
    return JSON.parse(result);
}

function etcdPut(key, value) {
    const decodedKey = Buffer.from(key, 'base64').toString();
    const decodedVal = Buffer.from(value, 'base64').toString();

    const cmd = `etcdctl --endpoints ${ETCD_ENDPOINT} put '${decodedKey}' '${decodedVal}'`;
    console.log("Executing command:", cmd);

    try {
        const output = execSync(cmd, { shell: true });
        console.log("etcdctl output:", output.toString());
    } catch (error) {
        console.error("etcdctl error:", error.message);
        console.error("stderr:", error.stderr?.toString());
        throw error;
    }
}

function detectFormat(filename, explicitFormat) {
    if (explicitFormat) return explicitFormat.toLowerCase();
    const ext = path.extname(filename).toLowerCase();
    return ext === '.yaml' || ext === '.yml' ? 'yaml' : 'json';
}

function writeFile(filename, data, format) {
    const content = format === 'yaml' 
        ? yaml.dump(data, { indent: 2, lineWidth: -1 })
        : JSON.stringify(data, null, 2);
    fs.writeFileSync(filename, content);
}

function readFile(filename, format) {
    const content = fs.readFileSync(filename, 'utf8');
    return format === 'yaml' ? yaml.load(content) : JSON.parse(content);
}

function main() {
    const args = process.argv.slice(2);
    let exportFile, importFile, format;
    
    // Parse arguments
    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--export':
                exportFile = args[++i];
                break;
            case '--import':
                importFile = args[++i];
                break;
            case '--format':
            case '-f':
                format = args[++i];
                break;
        }
    }
    
    if (exportFile) {
        const fileFormat = detectFormat(exportFile, format);
        const raw = etcdGetAll();
        const decoded = decodeEtcdExport(raw);
        writeFile(exportFile, decoded, fileFormat);
        console.log(`✅ Exported etcd to ${exportFile} (${fileFormat})`);
        
    } else if (importFile) {
        const fileFormat = detectFormat(importFile, format);
        const data = readFile(importFile, fileFormat);
        let count = 0;
        for (const [keyEnc, valEnc] of encodeEtcdImport(data)) {
            etcdPut(keyEnc, valEnc);
            count++;
        }
        console.log(`✅ Imported ${count} keys from ${importFile} (${fileFormat})`);
        
    } else {
        console.log('Usage:');
        console.log('  node apisix-etcd.js --export <outfile> [--format json|yaml]');
        console.log('  node apisix-etcd.js --import <infile> [--format json|yaml]');
        console.log('');
        console.log('Format auto-detected from file extension if not specified');
        console.log('(.json/.yaml/.yml)');
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}