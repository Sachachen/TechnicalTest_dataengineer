import os
import threading
from db import get_connection, init_db
from parsers import parse_and_store_ids, parse_and_store_access, parse_and_store_endpoint, ensure_indexes
from tailer import tail_file, tail_multiline_file

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IDS_LOG      = os.path.join(BASE, "Security-Log-Generator/logs/ids.log")
ACCESS_LOG   = os.path.join(BASE, "Security-Log-Generator/logs/access.log")
ENDPOINT_LOG = os.path.join(BASE, "Security-Log-Generator/logs/endpoint.log")


def main():
    # Init DB schema using a temporary connection
    conn = get_connection()
    init_db(conn)
    ensure_indexes(conn)  # ✅ Create indexes once at startup
    conn.close()          # Threads will open their own connections

    print("Pipeline started. Tailing log files...")

    threads = [
        threading.Thread(target=tail_file,           args=(IDS_LOG,      parse_and_store_ids),      daemon=True),
        threading.Thread(target=tail_file,           args=(ACCESS_LOG,   parse_and_store_access),   daemon=True),
        threading.Thread(target=tail_multiline_file, args=(ENDPOINT_LOG, parse_and_store_endpoint), daemon=True),
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()