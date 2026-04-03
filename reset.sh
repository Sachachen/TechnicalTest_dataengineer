#!/bin/bash

# Resolve the project root regardless of where the script is called from
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$PROJECT_DIR/.pids"

echo " Stopping all processes..."

if [ -f "$PID_FILE" ]; then
    while IFS= read -r pid; do
        # On Windows/Git Bash, use taskkill; on Unix, use kill
        if command -v taskkill &>/dev/null; then
            taskkill //F //PID "$pid" 2>/dev/null && echo "  Killed PID $pid"
        else
            kill "$pid" 2>/dev/null && echo "  Killed PID $pid"
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
else
    echo "  (No PID file found — falling back to taskkill by project path)"
    # Windows fallback: kill Python processes holding files in the project dir
    if command -v taskkill &>/dev/null; then
        # Kill all python/python3 processes — scoped as best we can on Windows
        taskkill //F //IM python.exe 2>/dev/null
        taskkill //F //IM python3.exe 2>/dev/null
    elif command -v pkill &>/dev/null; then
        pkill -f "$PROJECT_DIR" 2>/dev/null
    fi
fi

# Wait for processes to release file handles before deleting
sleep 2

echo "  Clearing database..."
rm -f "$PROJECT_DIR/pipeline/data/security.db"     2>/dev/null
rm -f "$PROJECT_DIR/pipeline/data/security.db-shm" 2>/dev/null
rm -f "$PROJECT_DIR/pipeline/data/security.db-wal" 2>/dev/null

echo "  Clearing log files..."
rm -f "$PROJECT_DIR/Security-Log-Generator/logs/ids.log"
rm -f "$PROJECT_DIR/Security-Log-Generator/logs/access.log"
rm -f "$PROJECT_DIR/Security-Log-Generator/logs/endpoint.log"

# Cleanup feed file
rm -f "$PROJECT_DIR/pipeline/data/ipsum.txt" 2>/dev/null

echo " Reset complete. Run ./start.sh to restart."