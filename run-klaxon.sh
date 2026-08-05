#!/usr/bin/env bash
set -a
. /home/marco/project/klaxon/.env
set +a
exec /home/marco/project/klaxon/.venv/bin/klaxon-mcp --transport http --host 192.168.2.57 --port 8000   


