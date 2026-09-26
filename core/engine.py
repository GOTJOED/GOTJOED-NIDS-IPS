import asyncio
import json
import os
import sqlite3
import requests
import threading
import sys
import re
import subprocess
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, BackgroundTasks, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field
import uvicorn

# Global connection state, threat indicator cache, and IPS state
active_dashboard_connections = set()
THREAT_INDICATORS_SET = set()
BANNED_IPS_CACHE = set()

# Workspace path resolution
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML_PATH = os.path.join(BASE_DIR, "web", "index.html")
FEEDS_DB_PATH = os.path.join(BASE_DIR, "db", "feeds.db")
LOGS_DB_PATH = os.path.join(BASE_DIR, "logs", "threat_events.db")
RULES_PATH = os.path.join(BASE_DIR, "rules", "custom.rules")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

shutdown_event = threading.Event()

# Enhanced Web Attack Regex Engine with MITRE CWE Mapping
PAYLOAD_PATTERNS = {
    "Path Traversal (CWE-22)": {
        "regex": re.compile(r"(/etc/passwd|\.\./\.\./|win\.ini|system32)", re.IGNORECASE),
        "cwe": "CWE-22",
        "desc": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "resolution": "Sanitize user inputs, enforce strict file path whitelisting, and restrict filesystem permissions.",
        "ref": "https://cwe.mitre.org/data/definitions/22.html"
    },
    "XSS Attack (CWE-79)": {
        "regex": re.compile(r"(<script|javascript:|onerror=|onload=)", re.IGNORECASE),
        "cwe": "CWE-79",
        "desc": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "resolution": "Implement Context-Aware Output Encoding and enforce Content Security Policy (CSP) headers.",
        "ref": "https://cwe.mitre.org/data/definitions/79.html"
    },
    "SQL Injection (CWE-89)": {
        "regex": re.compile(r"(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|INFORMATION_SCHEMA)", re.IGNORECASE),
        "cwe": "CWE-89",
        "desc": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "resolution": "Use parameterized queries (prepared statements) and ORM abstraction layers.",
        "ref": "https://cwe.mitre.org/data/definitions/89.html"
    },
    "Command Injection (CWE-78)": {
        "regex": re.compile(r"(;\s*cat\s+/etc|;\s*id\s*|;\s*whoami|\|\s*nc\s+)", re.IGNORECASE),
        "cwe": "CWE-78",
        "desc": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "resolution": "Avoid executing raw shell commands; use built-in language APIs with explicit parameter lists.",
        "ref": "https://cwe.mitre.org/data/definitions/78.html"
    }
}

PORT_SCAN_TRACKER = {}

# --- OPTIMIZED SQLITE LAYER ---

def get_db_conn(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA mmap_size=3000000000;")
    return conn

# --- PYDANTIC MODELS ---

class RetentionConfigModel(BaseModel):
    retention_days: int = Field(..., ge=1, le=365, description="Retention limit in days")
    max_db_size_mb: int = Field(500, ge=50, le=10000, description="Max DB cap before pruning")
    auto_ban_critical: bool = Field(True, description="Automatically trigger IPS ban on CRITICAL events")

class IPActionModel(BaseModel):
    ip: str = Field(..., description="Target IPv4 address")
    reason: str = Field("Manual Administrative Ban", description="Justification for banning")

def load_config() -> dict:
    default_config = {"retention_days": 7, "max_db_size_mb": 500, "auto_ban_critical": True}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                cfg = json.load(f)
                for k, v in default_config.items():
                    if k not in cfg: cfg[k] = v
                return cfg
        except Exception as e:
            print(f"[!] Warning reading config.json: {e}")
    else:
        save_config(default_config)
    return default_config

def save_config(cfg: dict):
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[!] Error writing config.json: {e}")

# --- IPS ENGINE: HIGH PERFORMANCE IPSET O(1) INTEGRATION ---

def sync_ips_state():
    global BANNED_IPS_CACHE
    try:
        subprocess.run(["ipset", "create", "nids_banned", "hash:ip"], stderr=subprocess.DEVNULL)
        
        chk = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "nids_banned", "src", "-j", "DROP"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if chk.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "nids_banned", "src", "-j", "DROP"])

        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT ip FROM banned_ips")
        rows = c.fetchall()
        conn.close()
        
        BANNED_IPS_CACHE = {r[0] for r in rows}
        
        for ip in BANNED_IPS_CACHE:
            subprocess.run(["ipset", "-!", "add", "nids_banned", ip], stderr=subprocess.DEVNULL)
            
        print(f"[*] Loaded {len(BANNED_IPS_CACHE)} active banned hosts into RAM cache & Kernel IPSet.")
    except Exception as e:
        print(f"[!] IPS State Sync Issue: {e}")

def execute_system_ban(ip: str) -> bool:
    if not ip or ip in ("N/A", "127.0.0.1", "0.0.0.0"): return False
    try:
        res = subprocess.run(["ipset", "-!", "add", "nids_banned", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            print(f"[IPS ACTIVE DROP] Successfully added host to IPSet memory pool: {ip}")
            return True
        return False
    except Exception as e:
        print(f"[!] IPSet Execution Exception: {e}")
        return False

def execute_system_unban(ip: str) -> bool:
    try:
        res = subprocess.run(["ipset", "-!", "del", "nids_banned", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return res.returncode == 0
    except Exception as e:
        print(f"[!] IPSet Unban Exception: {e}")
        return False

def ban_host(ip: str, reason: str = "IPS Threat Escalation") -> bool:
    if not ip or ip == "N/A": return False
    execute_system_ban(ip)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at) VALUES (?, ?, ?)", (ip, reason, now))
        conn.commit()
        conn.close()
        BANNED_IPS_CACHE.add(ip)
        
        if active_dashboard_connections:
            payload = json.dumps({"type": "IPS_BAN", "ip": ip, "reason": reason, "time": now})
            main_loop = asyncio.get_event_loop()
            for connection in list(active_dashboard_connections):
                asyncio.run_coroutine_threadsafe(connection.send_text(payload), main_loop)
        return True
    except Exception as e:
        return False

def unban_host(ip: str) -> bool:
    execute_system_unban(ip)
    try:
        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        BANNED_IPS_CACHE.discard(ip)
        
        if active_dashboard_connections:
            payload = json.dumps({"type": "IPS_UNBAN", "ip": ip})
            main_loop = asyncio.get_event_loop()
            for connection in list(active_dashboard_connections):
                asyncio.run_coroutine_threadsafe(connection.send_text(payload), main_loop)
        return True
    except Exception as e:
        return False

# --- ENGINE CORE & DATABASE ---

def prune_logs_now() -> dict:
    if not os.path.exists(LOGS_DB_PATH):
        return {"deleted_rows": 0, "emergency_pruned": False}

    config = load_config()
    retention_days = config.get("retention_days", 7)
    max_bytes = config.get("max_db_size_mb", 500) * 1024 * 1024
    
    deleted_count = 0
    emergency_triggered = False

    try:
        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()

        cutoff_date = (datetime.now() - timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")
        c.execute("DELETE FROM threat_logs WHERE timestamp < ?", (cutoff_date,))
        deleted_count = c.rowcount

        db_size = os.path.getsize(LOGS_DB_PATH) if os.path.exists(LOGS_DB_PATH) else 0
        if db_size > max_bytes:
            emergency_triggered = True
            c.execute("""
                DELETE FROM threat_logs 
                WHERE id IN (SELECT id FROM threat_logs ORDER BY id ASC LIMIT (SELECT COUNT(*) / 10 FROM threat_logs))
            """)
            c.execute("PRAGMA wal_checkpoint(TRUNCATE);")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Retention Pruning Exception: {e}")

    return {"deleted_rows": deleted_count, "emergency_pruned": emergency_triggered}

async def retention_manager():
    while not shutdown_event.is_set():
        await asyncio.sleep(300)
        await asyncio.to_thread(prune_logs_now)

def init_db():
    conn_feeds = get_db_conn(FEEDS_DB_PATH)
    cf = conn_feeds.cursor()
    cf.execute('''CREATE TABLE IF NOT EXISTS feeds 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, indicator TEXT UNIQUE, 
                  type TEXT, description TEXT, resolution TEXT, ref_url TEXT, added_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    cf.execute('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)''')
    
    # Ingest baseline CWE signatures
    for name, info in PAYLOAD_PATTERNS.items():
        cwe_id = info["cwe"]
        cf.execute("""
            INSERT OR IGNORE INTO feeds (source, indicator, type, description, resolution, ref_url)
            VALUES ('MITRE CWE', ?, 'CWE', ?, ?, ?)
        """, (cwe_id, info["desc"], info["resolution"], info["ref"]))
        
    conn_feeds.commit()
    conn_feeds.close()

    conn_logs = get_db_conn(LOGS_DB_PATH)
    cl = conn_logs.cursor()
    cl.execute('''CREATE TABLE IF NOT EXISTS threat_logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src TEXT, dst TEXT, 
                  proto TEXT, info TEXT, severity TEXT, action_taken TEXT DEFAULT 'ALERT', payload TEXT DEFAULT '')''')
    
    try: cl.execute("ALTER TABLE threat_logs ADD COLUMN action_taken TEXT DEFAULT 'ALERT'")
    except sqlite3.OperationalError: pass
    try: cl.execute("ALTER TABLE threat_logs ADD COLUMN payload TEXT DEFAULT ''")
    except sqlite3.OperationalError: pass

    cl.execute('''CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, reason TEXT, banned_at TEXT)''')
    conn_logs.commit()
    conn_logs.close()

def load_threat_cache():
    global THREAT_INDICATORS_SET
    try:
        conn = get_db_conn(FEEDS_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT indicator FROM feeds")
        rows = c.fetchall()
        conn.close()
        THREAT_INDICATORS_SET = {r[0].strip() for r in rows if r[0]}
    except Exception as e: pass

def log_threat_event(src, dst, proto, info, severity="HIGH", payload_data=""):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    config = load_config()
    action_taken = "ALERT"
    
    if src in BANNED_IPS_CACHE:
        action_taken = "BANNED"
    elif config.get("auto_ban_critical", True) and severity == "CRITICAL" and src and src != "N/A":
        if ban_host(src, f"Auto-Ban IPS: {info}"):
            action_taken = "BANNED"

    print(f"\n\033[91m[!!! IPS ALERT ({action_taken}) !!!] [{severity}] {src} -> {dst} | {info}\033[0m\n", flush=True)

    try:
        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO threat_logs (timestamp, src, dst, proto, info, severity, action_taken, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (now, src, dst, proto, info, severity, action_taken, payload_data))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Threat Logging Error: {e}")

    if active_dashboard_connections:
        data_payload = {
            "type": "NEW_THREAT", "time": datetime.now().strftime("%H:%M:%S"), "timestamp": now,
            "protocol": proto, "src": src, "dst": dst, "info": info, "severity": severity,
            "action_taken": action_taken, "payload": payload_data
        }
        json_data = json.dumps(data_payload)
        main_loop = asyncio.get_event_loop()
        for connection in list(active_dashboard_connections):
            asyncio.run_coroutine_threadsafe(connection.send_text(json_data), main_loop)

def analyze_packet_data(src, dst, proto, info, uri=""):
    full_payload = f"{info} {uri}".strip()

    # Dynamic CVE Pattern Extractor from incoming traffic
    cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", full_payload, re.IGNORECASE)
    if cve_match:
        cve_id = cve_match.group(1).upper()
        log_threat_event(src, dst, proto, f"[EXPLOIT ATTEMPT] {cve_id}: Targeted Payload Injection", 
                         severity="CRITICAL", payload_data=full_payload)
        return

    # Check Intelligence Feeds (Abuse.ch, CISA KEV, ET Open)
    if src in THREAT_INDICATORS_SET or dst in THREAT_INDICATORS_SET:
        matched_ip = src if src in THREAT_INDICATORS_SET else dst
        log_threat_event(src, dst, proto, f"[INTEL MATCH] C2 / Malicious Infrastructure ({matched_ip})", 
                         severity="CRITICAL", payload_data=full_payload)
        return

    # Check Web Attack Signatures & CWE Patterns
    for attack_name, pat_info in PAYLOAD_PATTERNS.items():
        if pat_info["regex"].search(full_payload):
            cwe_tag = pat_info["cwe"]
            log_threat_event(src, dst, proto, f"WEB ATTACK: {attack_name} [{cwe_tag}]", 
                             severity="CRITICAL", payload_data=full_payload)
            return

    # Port Scan Analytics
    if proto in ["TCP", "UDP"] and src and src != 'N/A':
        now_ts = datetime.now().timestamp()
        tracker = PORT_SCAN_TRACKER.get(src, {"ports": set(), "last_seen": now_ts})
        
        if now_ts - tracker["last_seen"] > 5:
            tracker["ports"] = set()
        
        port_match = re.search(r'>\s*(\d+)', info)
        if port_match:
            tracker["ports"].add(port_match.group(1))
            tracker["last_seen"] = now_ts
            PORT_SCAN_TRACKER[src] = tracker
            
            if len(tracker["ports"]) >= 5:
                log_threat_event(src, dst, proto, f"PORT SCAN DETECTED: Probed {len(tracker['ports'])} ports in 5s window", 
                                 severity="HIGH", payload_data=f"Targeted ports: {', '.join(list(tracker['ports'])[:10])}")
                tracker["ports"].clear()

async def native_tshark_stream():
    print("[*] Initializing Native TShark packet stream...")
    cmd = ["tshark", "-i", "any", "-l", "-n", "-q", "-T", "fields", "-E", "separator=|",
           "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info", "-e", "http.request.uri"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        while not shutdown_event.is_set():
            line = await proc.stdout.readline()
            if not line: break
            decoded = line.decode('utf-8', errors='ignore').strip()
            parts = decoded.split('|')
            if len(parts) >= 4:
                src, dst, proto, info = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
                uri = parts[4].strip() if len(parts) > 4 else ""
                analyze_packet_data(src, dst, proto, info, uri)
    except asyncio.CancelledError:
        proc.terminate()
    except Exception as e:
        if not shutdown_event.is_set(): print(f"[!] Native TShark Stream Exception: {e}")
    finally:
        print("[*] TShark packet stream terminated.")

# --- COMPLETE DYNAMIC FEED FETCHING LOGIC ---
def _fetch_feeds_sync(force=False):
    print("[*] Evaluating threat intelligence feed status...")
    
    # --- FAST STARTUP & OFFLINE CACHE CHECK ---
    # If not forcefully triggered and files already exist, skip the network request
    if not force and os.path.exists(RULES_PATH) and os.path.exists(FEEDS_DB_PATH):
        try:
            conn = get_db_conn(FEEDS_DB_PATH)
            c = conn.cursor()
            # Check if we actually have downloaded feeds (excluding the local MITRE CWEs)
            c.execute("SELECT COUNT(*) FROM feeds WHERE source != 'MITRE CWE'")
            count = c.fetchone()[0]
            conn.close()
            
            if count > 0:
                print(f"[*] Found {count} existing threat signatures. Skipping network download for ultra-fast startup!")
                print("[*] (Tip: You can force a feed update anytime via the Dashboard UI).")
                load_threat_cache()
                return
        except Exception:
            pass
    # ------------------------------------------

    print("[*] Downloading latest threat intelligence feeds via Network...")
    conn = get_db_conn(FEEDS_DB_PATH)
    c = conn.cursor()

    # 1. Abuse.ch Feodo Tracker (C2 IPs)
    try:
        print("  -> Fetching Abuse.ch IP blocklist...")
        resp = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.startswith("#") or not line.strip(): continue
                indicator = line.strip()
                ref_link = f"https://feodotracker.abuse.ch/browse/host/{indicator}/"
                c.execute("""
                    INSERT OR REPLACE INTO feeds (source, indicator, type, description, resolution, ref_url) 
                    VALUES ('Abuse.ch', ?, 'IP', 'Known C2/Botnet Infrastructure', 'Block IP immediately via IPS IPSet rule.', ?)
                """, (indicator, ref_link))
    except Exception as e: 
        print(f"[!] Error fetching Abuse.ch: Network/DNS unavailable.")

    # 2. CISA KEV (Known Exploited Vulnerabilities - CVE Records)
    try:
        print("  -> Fetching CISA KEV catalog...")
        resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "").strip().upper()
                if not cve_id: continue
                desc = vuln.get("shortDescription", "CISA KEV Catalogued Vulnerability")
                action = vuln.get("requiredAction", "Apply updates as per official vendor advisories.")
                primary_cve_link = f"https://www.cve.org/CVERecord?id={cve_id}"
                c.execute("""
                    INSERT OR REPLACE INTO feeds (source, indicator, type, description, resolution, ref_url)
                    VALUES ('CISA KEV', ?, 'CVE', ?, ?, ?)
                """, (cve_id, desc, action, primary_cve_link))
    except Exception as e: 
        print(f"[!] Error fetching CISA KEV: Network/DNS unavailable.")

    # 3. ET Open Suricata Rules Ingestion & Dynamic Rule Ingestion
    try:
        print("  -> Fetching Emerging Threats (ET Open) Malware rules...")
        rule_url = "https://rules.emergingthreats.net/open/suricata/rules/emerging-malware.rules"
        resp = requests.get(rule_url, timeout=15)
        if resp.status_code == 200:
            rules_text = resp.text
            with open(RULES_PATH, "w", encoding="utf-8") as f:
                f.write(rules_text)
            
            # Parse rules dynamically into DB
            for line in rules_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                msg_match = re.search(r'msg:\s*"([^"]+)";', line)
                sid_match = re.search(r'sid:\s*(\d+);', line)
                cve_match = re.search(r'reference:\s*cve,\s*([\d\-]+)', line, re.IGNORECASE)
                
                if msg_match and sid_match:
                    msg = msg_match.group(1)
                    sid = sid_match.group(1)
                    cve_id = f"CVE-{cve_match.group(1)}" if cve_match else f"ET-SID-{sid}"
                    ref_url = f"https://www.cve.org/CVERecord?id={cve_id}" if cve_match else f"https://doc.emergingthreats.net/{sid}"
                    c.execute("""
                        INSERT OR REPLACE INTO feeds (source, indicator, type, description, resolution, ref_url)
                        VALUES ('ET Open', ?, 'SIGNATURE', ?, 'Inspect network payload and apply firewall drop rule.', ?)
                    """, (cve_id, f"[SID:{sid}] {msg}", ref_url))
                    
            print(f"  -> Successfully wrote and parsed ET Open rules into DB.")
    except Exception as e: 
        print(f"[!] Error fetching ET Open rules: Network/DNS unavailable.")

    sync_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_sync', ?)", (sync_time,))
    conn.commit()
    conn.close()
    
    load_threat_cache()
    print("[*] Threat intelligence feeds successfully updated.")

async def fetch_threat_feeds(force=False):
    await asyncio.to_thread(_fetch_feeds_sync, force)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    load_threat_cache()
    sync_ips_state()
    asyncio.create_task(fetch_threat_feeds())
    asyncio.create_task(retention_manager())
    capture_task = asyncio.create_task(native_tshark_stream())
    yield
    shutdown_event.set()
    capture_task.cancel()

app = FastAPI(title="GOT JOED NIDS/IPS Engine", lifespan=lifespan)

# --- REST API ENDPOINTS ---

@app.get("/api/settings")
async def get_settings():
    cfg = load_config()
    db_size_mb, total_logs, crit_count, high_count, today_count = 0.0, 0, 0, 0, 0

    if os.path.exists(LOGS_DB_PATH):
        db_size_mb = round(os.path.getsize(LOGS_DB_PATH) / (1024 * 1024), 2)
        try:
            conn = get_db_conn(LOGS_DB_PATH)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM threat_logs")
            total_logs = c.fetchone()[0]
            today = datetime.now().strftime("%Y-%m-%d")
            c.execute("SELECT severity, COUNT(*) FROM threat_logs WHERE timestamp LIKE ? GROUP BY severity", (f"{today}%",))
            counts = dict(c.fetchall())
            crit_count, high_count, today_count = counts.get("CRITICAL", 0), counts.get("HIGH", 0), sum(counts.values())
            conn.close()
        except Exception: pass

    return {
        "retention_days": cfg.get("retention_days", 7), "max_db_size_mb": cfg.get("max_db_size_mb", 500),
        "auto_ban_critical": cfg.get("auto_ban_critical", True), "current_db_size_mb": db_size_mb,
        "total_logged_events": total_logs, "today_count": today_count, "crit_count": crit_count,
        "high_count": high_count, "banned_ips_count": len(BANNED_IPS_CACHE)
    }

@app.post("/api/settings/retention")
async def update_retention_settings(config_data: RetentionConfigModel):
    cfg = load_config()
    cfg["retention_days"] = config_data.retention_days
    cfg["max_db_size_mb"] = config_data.max_db_size_mb
    cfg["auto_ban_critical"] = config_data.auto_ban_critical
    save_config(cfg)
    prune_res = await asyncio.to_thread(prune_logs_now)
    return {"status": "success", "message": "Retention policy & IPS controls updated.", "prune_summary": prune_res}

@app.post("/api/settings/prune")
async def manual_prune_trigger():
    return {"status": "success", "summary": await asyncio.to_thread(prune_logs_now)}

@app.get("/api/logs")
async def get_threat_logs(limit: int = 250, severity: str = "All", search: str = "", hours: int = 0):
    try:
        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()
        query = "SELECT id, timestamp, src, dst, proto, info, severity, action_taken, payload FROM threat_logs WHERE 1=1"
        params = []
        if severity != "All":
            query += " AND severity = ?"
            params.append(severity.upper())
        if search:
            query += " AND (src LIKE ? OR dst LIKE ? OR info LIKE ? OR payload LIKE ?)"
            search_term = f"%{search}%"
            params.extend([search_term, search_term, search_term, search_term])
        if hours > 0:
            query += " AND timestamp >= ?"
            params.append((datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S"))
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        return [{"id": r[0], "timestamp": r[1], "src": r[2], "dst": r[3], "proto": r[4], "info": r[5], "severity": r[6], "action_taken": r[7] or "ALERT", "payload": r[8] or ""} for r in rows]
    except Exception: return []

@app.get("/api/ips/banned")
async def get_banned_hosts():
    try:
        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT ip, reason, banned_at FROM banned_ips ORDER BY banned_at DESC")
        rows = c.fetchall()
        conn.close()
        return [{"ip": r[0], "reason": r[1], "banned_at": r[2]} for r in rows]
    except Exception: return []

@app.post("/api/ips/ban")
async def api_ban_ip(payload: IPActionModel):
    if ban_host(payload.ip, payload.reason): return {"status": "success"}
    raise HTTPException(status_code=400, detail="Failed to apply IPS ban.")

@app.post("/api/ips/unban")
async def api_unban_ip(payload: IPActionModel):
    if unban_host(payload.ip): return {"status": "success"}
    raise HTTPException(status_code=400, detail="Failed to unban host.")

@app.delete("/api/logs/purge")
async def purge_all_logs():
    try:
        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM threat_logs")
        conn.commit()
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/logs/{log_id}")
async def delete_single_log(log_id: int):
    try:
        conn = get_db_conn(LOGS_DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM threat_logs WHERE id = ?", (log_id,))
        conn.commit()
        conn.close()
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- DYNAMIC CVE INTEL & REFERENCE RESOLVER ---

@app.get("/api/feeds/status")
async def get_feeds_status():
    try:
        conn = get_db_conn(FEEDS_DB_PATH)
        c = conn.cursor()
        
        c.execute("SELECT value FROM metadata WHERE key='last_sync'")
        row = c.fetchone()
        last_sync = row[0] if row else "Never Synced"
        
        c.execute("SELECT COUNT(*) FROM feeds")
        total = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM feeds WHERE source='Abuse.ch'")
        abuse = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM feeds WHERE source='CISA KEV'")
        cisa = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM feeds WHERE source='ET Open'")
        et_count = c.fetchone()[0]
        conn.close()
        
        return {
            "version": "1.0 Active",
            "last_sync": last_sync,
            "total_active": total,
            "abuse_ch_c2": abuse,
            "cisa_kev": cisa,
            "et_open": et_count
        }
    except Exception as e:
        return {"version": "Error", "last_sync": "Unknown", "total_active": 0, "abuse_ch_c2": 0, "cisa_kev": 0, "et_open": 0}

@app.post("/api/feeds/update")
async def trigger_feed_update():
    # Pass force=True so the manual button always downloads updates
    asyncio.create_task(fetch_threat_feeds(force=True))
    return {"status": "success", "message": "Manual feed sync initiated. Signatures are updating in the background."}

@app.get("/api/cve/lookup")
async def cve_lookup(indicator: str = ""):
    if not indicator:
        return {"found": False}
        
    indicator_clean = indicator.strip()
    
    # Extract CVE-YYYY-NNNN if present in signature info
    cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", indicator_clean, re.IGNORECASE)
    extracted_cve = cve_match.group(1).upper() if cve_match else None
    
    # Check CWE
    cwe_match = re.search(r"(CWE-\d+)", indicator_clean, re.IGNORECASE)
    extracted_cwe = cwe_match.group(1).upper() if cwe_match else None

    try:
        conn = get_db_conn(FEEDS_DB_PATH)
        c = conn.cursor()
        
        target_term = extracted_cve or extracted_cwe or indicator_clean
        search_like = f"%{target_term}%"
        
        c.execute("SELECT source, indicator, description, resolution, ref_url FROM feeds WHERE indicator = ? OR indicator LIKE ? OR description LIKE ? LIMIT 1",
                  (target_term, search_like, search_like))
        row = c.fetchone()
        conn.close()

        if row:
            source, found_ind, desc, res, ref_url = row[0], row[1], row[2], row[3], row[4]
            final_cve = extracted_cve if extracted_cve else (found_ind if found_ind.startswith("CVE-") else None)
            
            primary_url = ref_url
            secondary_url = None
            
            if final_cve:
                primary_url = f"https://www.cve.org/CVERecord?id={final_cve}"
                secondary_url = f"https://senserva.com/cve/{final_cve}.html"
            elif not primary_url:
                primary_url = "https://cve.mitre.org/"

            return {
                "found": True,
                "cve_id": final_cve or target_term,
                "source": source,
                "description": desc,
                "resolution": res or "Enforce immediate firewall block and audit host processes.",
                "ref_url": primary_url,
                "secondary_ref_url": secondary_url
            }
    except Exception as e:
        print(f"[!] CVE Lookup Error: {e}")

    # Fallback if CVE ID was extracted but not stored in local cache
    if extracted_cve:
        return {
            "found": True,
            "cve_id": extracted_cve,
            "source": "Global Vulnerability Intel",
            "description": f"Targeted payload matched {extracted_cve} exploit signature pattern.",
            "resolution": "Apply official vendor security patch immediately and block source host IP.",
            "ref_url": f"https://www.cve.org/CVERecord?id={extracted_cve}",
            "secondary_ref_url": f"https://senserva.com/cve/{extracted_cve}.html"
        }

    return {"found": False}

@app.get("/")
async def serve_dashboard():
    return FileResponse(INDEX_HTML_PATH) if os.path.exists(INDEX_HTML_PATH) else HTMLResponse("<h1>NIDS Active</h1>")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_dashboard_connections.add(websocket)
    try:
        while True: await websocket.receive_text()
    except Exception:
        active_dashboard_connections.discard(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=11050, log_level="error")