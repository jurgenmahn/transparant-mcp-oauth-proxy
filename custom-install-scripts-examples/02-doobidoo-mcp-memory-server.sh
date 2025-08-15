#! /bin/bash

mkdir -p /doobidoo-mcp-memory-server && cd /doobidoo-mcp-memory-server
git clone https://github.com/doobidoo/mcp-memory-service.git
cd mcp-memory-service

python3 -m venv venv
source venv/bin/activate
python3 install.py --skip-multi-client-prompt

mkdir -p /workspace/mcp-memory/db && mkdir -p /workspace/mcp-memory/backups