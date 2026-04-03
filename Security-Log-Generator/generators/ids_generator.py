import random
import ipaddress
import sqlite3
import os
import time
from fields import ids_fields
from events import ids_event


# Load top malicious IPs from shared SQLite feed.
def _load_malicious_ips() -> list:
    db_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "pipeline", "data", "security.db"
    )
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.execute("PRAGMA busy_timeout=5000;")
        rows = conn.execute(
            "SELECT ip FROM malicious_ips ORDER BY score DESC LIMIT 500"
        ).fetchall()
        conn.close()
        if rows:
            print(f"[ids_generator] Loaded {len(rows)} malicious IPs for injection")
        return [r[0] for r in rows]
    except Exception as e:
        print(f"[ids_generator] Could not load malicious IPs: {e}")
        return []

MALICIOUS_IPS = []
_LAST_LOAD_ATTEMPT = 0.0
_RETRY_SECONDS = 10.0


def _refresh_malicious_ips_if_needed(force: bool = False) -> None:
    """Retry loading periodically so startup races do not leave cache empty."""
    global MALICIOUS_IPS, _LAST_LOAD_ATTEMPT
    now = time.monotonic()
    if not force and MALICIOUS_IPS:
        return
    if not force and (now - _LAST_LOAD_ATTEMPT) < _RETRY_SECONDS:
        return

    _LAST_LOAD_ATTEMPT = now
    ips = _load_malicious_ips()
    if ips:
        MALICIOUS_IPS = ips


_refresh_malicious_ips_if_needed(force=True)


# maps common port values to the correct protocol
def get_port(protocol):
    protocol_to_port = {
        'TCP': random.randint(1, 65535),
        'UDP': random.randint(1, 65535),
        'ICMP': 1,
        'HTTP': 80,
        'HTTPS': 443,
        'FTP': 21,
        'SMTP': 25,
        'DNS': 53,
        'DHCP': 67,
        'TFTP': 69,
        'SNMP': 161
    }
    return protocol_to_port.get(protocol, random.randint(1, 65535))


# generates a random valid ip address — with 3% chance of returning a real malicious IP
def get_ip() -> str:
    _refresh_malicious_ips_if_needed()
    if MALICIOUS_IPS and random.random() < 0.10:
        return random.choice(MALICIOUS_IPS)

    octet1 = random.randint(0, 255)
    octet2 = random.randint(0, 255)
    octet3 = random.randint(0, 255)
    octet4 = random.randint(0, 255)
    return f"{octet1}.{octet2}.{octet3}.{octet4}"  # returns plain string ✅


# gather and generate values for fields and construct into ids event class object
def make_event():
    event_severity   = random.choices(ids_fields.SEVERITY,          ids_fields.SEVERITY_WEIGHTS)[0]
    event_protocol   = random.choices(ids_fields.PROTOCOL,          ids_fields.PROTOCOL_WEIGHTS)[0]
    event_flag       = random.choices(ids_fields.FLAG,               ids_fields.FLAG_WEIGHTS)[0]
    event_alert_desc = random.choices(ids_fields.ALERT_DESCRIPTION,  ids_fields.ALERT_WEIGHTS)[0]

    event_src_ip   = get_ip()
    event_dest_ip  = get_ip()

    event_src_port  = random.randint(1, 65535)
    event_dest_port = get_port(event_protocol)

    event = ids_event(
        event_severity, event_protocol,
        event_src_ip, event_dest_ip,
        event_src_port, event_dest_port,
        event_flag, event_alert_desc
    )
    return event
