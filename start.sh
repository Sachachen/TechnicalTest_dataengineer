#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
GEN_DIR="$PROJECT_DIR/Security-Log-Generator"
PIPELINE_DIR="$PROJECT_DIR/pipeline"
LOG_DIR="$GEN_DIR/logs"
PID_FILE="$PROJECT_DIR/.pids"

if [ -f "$PID_FILE" ]; then
    echo " Killing leftover processes from previous session..."
    while IFS= read -r pid; do
        if command -v taskkill &>/dev/null; then
            taskkill //F //PID "$pid" 2>/dev/null
        else
            kill "$pid" 2>/dev/null
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
    sleep 1
fi

# Kill anything still holding port 8050 (Windows-compatible)
if command -v taskkill &>/dev/null && command -v netstat &>/dev/null; then
    netstat -ano 2>/dev/null | grep ":8050 " | awk '{print $5}' | sort -u | while IFS= read -r pid; do
        [ "$pid" != "0" ] && taskkill //F //PID "$pid" 2>/dev/null
    done
elif command -v fuser &>/dev/null; then
    fuser -k 8050/tcp 2>/dev/null
fi

> "$PID_FILE"

echo " Starting CYNA Security Pipeline..."

echo " Fetching IPsum threat feed..."
cd "$PIPELINE_DIR"
python fetch_ipsum.py \
    --db "$PROJECT_DIR/pipeline/data/security.db" \
    --output "$PROJECT_DIR/pipeline/data/ipsum.txt" \
    --daemon --interval-hours 24 &
IPSUM_PID=$!
echo "$IPSUM_PID" >> "$PID_FILE"
echo " IPsum scheduler started (PID $IPSUM_PID, refresh every 24 h)."

echo " Waiting for IPsum feed to load..."
DB="$PROJECT_DIR/pipeline/data/security.db"
until python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]).cursor(); c.execute('SELECT COUNT(*) FROM malicious_ips'); sys.exit(0 if c.fetchone()[0]>0 else 1)" "$DB" 2>/dev/null; do
    sleep 1
done
echo " IPsum loaded — malicious_ips table ready."

mkdir -p "$LOG_DIR"

echo " Starting log generators..."

cd "$GEN_DIR"

python -c "
import sys, os
sys.path.insert(0, '$GEN_DIR')
import logger, time
from generators.ids_generator import make_event
log = logger.ids_logger('INFO')
for _ in range(999999):
    e = make_event()
    log.info(f'{e.severity} - {e.protocol} - {e.src_ip}:{e.src_port} --> {e.dest_ip}:{e.dest_port} - {e.flags} - {e.alert_desc}')
    time.sleep(0.001)
" &
IDS_PID=$!
echo "$IDS_PID" >> "$PID_FILE"
echo " IDS generator started (PID $IDS_PID)"

python -c "
import sys
sys.path.insert(0, '$GEN_DIR')
import logger, time
from generators.access_generator import make_event
log = logger.access_logger('INFO')
for _ in range(999999):
    e = make_event()
    log.info(f'{e.client_ip} - {e.user} \"{e.method} {e.resource} {e.protocol} {e.status} {e.bytes} {e.referrer}\" \"{e.user_agent}\"')
    time.sleep(0.001)
" &
ACCESS_PID=$!
echo "$ACCESS_PID" >> "$PID_FILE"
echo " Access generator started (PID $ACCESS_PID)"

python -c "
import sys
sys.path.insert(0, '$GEN_DIR')
import logger, time
from generators.endpoint_generator import make_event
log = logger.endpoint_logger('INFO')
for _ in range(999999):
    e = make_event()
    if e.event_type == 'Malware Detected':
        log.info(f'\nEvent Type: {e.event_type}\nFile Name: {e.file_name}\nThreat Name: {e.threat_name}\nAction Taken: {e.action_taken}\nUser: {e.user}\nComputer: {e.computer}')
    elif e.event_type in ['Scan Started', 'Scan Completed']:
        log.info(f'\nEvent Type: {e.event_type}\nScan Type: {e.scan_type}\nUser: {e.user}\nComputer: {e.computer}')
    elif e.event_type == 'Update Applied':
        log.info(f'\nEvent Type: {e.event_type}\nUpdate Type: {e.update_type}\nUser: {e.user}\nComputer: {e.computer}')
    else:
        log.info(f'\nEvent Type: {e.event_type}\nUser: {e.user}\nComputer: {e.computer}')
    time.sleep(0.001)
" &
ENDPOINT_PID=$!
echo "$ENDPOINT_PID" >> "$PID_FILE"
echo " Endpoint generator started (PID $ENDPOINT_PID)"

echo " Waiting for log files to be created..."
while [ ! -f "$LOG_DIR/ids.log" ] || [ ! -f "$LOG_DIR/access.log" ] || [ ! -f "$LOG_DIR/endpoint.log" ]; do
    sleep 1
done
echo " Log files detected."

echo "  Starting enrichment pipeline..."
cd "$PROJECT_DIR"
python pipeline/main.py &
PIPELINE_PID=$!
echo "$PIPELINE_PID" >> "$PID_FILE"
echo " Pipeline started (PID $PIPELINE_PID)"

echo " Starting dashboard..."
cd "$PROJECT_DIR/dashboard"
python app.py &
DASHBOARD_PID=$!
echo "$DASHBOARD_PID" >> "$PID_FILE"
echo " Dashboard started at http://localhost:8050"

echo ""
echo " All services running. Press Ctrl+C to stop."

trap "echo ' Stopping...'; kill $IPSUM_PID $IDS_PID $ACCESS_PID $ENDPOINT_PID $PIPELINE_PID $DASHBOARD_PID 2>/dev/null; rm -f '$PID_FILE'; echo 'Done.'; exit 0" SIGINT SIGTERM

wait