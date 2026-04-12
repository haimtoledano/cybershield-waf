import os
import json
import time
import threading
import traceback
from datetime import datetime, timedelta
from dateutil.parser import parse as parse_date
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://waf_admin:waf_password@db:5432/waf_db")
LOG_FILE = "/app/envoy-dynamic/access.log"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def retention_worker():
    while True:
        try:
            with SessionLocal() as db:
                print("[Retention] Running retention policy check...", flush=True)
                # Build list of active servers to cleanup
                servers = db.execute(text("SELECT id, log_retention_days FROM virtual_servers")).fetchall()
                for server in servers:
                    vs_id = server[0]
                    retention_days = server[1] or 7
                    cutoff = datetime.utcnow() - timedelta(days=retention_days)
                    deleted = db.execute(
                        text("DELETE FROM access_logs WHERE vs_id = :vs_id AND timestamp < :cutoff"),
                        {"vs_id": vs_id, "cutoff": cutoff}
                    ).rowcount
                    if deleted > 0:
                        print(f"[Retention] Deleted {deleted} logs for VS {vs_id}")
                
                # Cleanup Expired IP Rules
                deleted_ips = db.execute(
                    text("DELETE FROM ip_rules WHERE expires_at IS NOT NULL AND expires_at < :now"),
                    {"now": datetime.utcnow()}
                ).rowcount
                if deleted_ips > 0:
                    print(f"[Retention] Deleted {deleted_ips} expired dynamic IP Blacklists")
                    db.commit()
                    import requests
                    try: requests.post("http://waf-backend:8000/api/internal/trigger-update", timeout=1)
                    except: pass
                else:
                    db.commit()
                        
        except Exception as e:
            print(f"[Retention] Error: {e}", flush=True)
            import traceback
            traceback.print_exc()
        
        time.sleep(60)

def tail_logs():
    print(f"[Logger] Waiting for {LOG_FILE} to exist...", flush=True)
    while not os.path.exists(LOG_FILE):
        time.sleep(2)
        
    print(f"[Logger] Started tailing {LOG_FILE}", flush=True)
    with open(LOG_FILE, 'r') as f:
        # Go to the end of file (or we could read from start if we want to ingest missed logs)
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
                
            line = line.strip()
            if not line:
                continue
                
            try:
                log_entry = json.loads(line)
                process_log_entry(log_entry)
            except json.JSONDecodeError:
                print(f"[Logger] Failed to decode JSON: {line}", flush=True)
            except Exception as e:
                print(f"[Logger] Error processing log: {e}", flush=True)

def process_log_entry(entry):
    server_name = entry.get("server")
    if not server_name:
        return
        
    with SessionLocal() as db:
        # Find VS ID by name
        res = db.execute(text("SELECT id FROM virtual_servers WHERE name = :name LIMIT 1"), {"name": server_name}).fetchone()
        vs_id = res[0] if res else server_name
        
        # Parse timestamp safely
        try:
            timestamp = parse_date(entry.get("time"))
        except:
            timestamp = datetime.utcnow()
            
        status_code = entry.get("status")
        try:
            status_code = int(status_code)
        except:
            status_code = 0
            
        req_body = entry.get("req_body")
        resp_body = entry.get("resp_body")
        
        # Truncate payloads to 10kb
        if req_body and len(req_body) > 10240:
            req_body = req_body[:10240] + "\n...[TRUNCATED]"
        if resp_body and len(resp_body) > 10240:
            resp_body = resp_body[:10240] + "\n...[TRUNCATED]"

        # Insert into access_logs
        db.execute(
            text("""
            INSERT INTO access_logs (id, vs_id, timestamp, method, path, status_code, client_ip, user_agent, req_payload, resp_payload, block_reason)
            VALUES (:id, :vs_id, :ts, :method, :path, :status, :ip, :ua, :req, :resp, :reason)
            """),
            {
                "id": str(os.urandom(16).hex()),
                "vs_id": vs_id,
                "ts": timestamp,
                "method": entry.get("method") or "UNKNOWN",
                "path": entry.get("path") or "/",
                "status": status_code,
                "ip": entry.get("client_ip") or "0.0.0.0",
                "ua": entry.get("user_agent") or "Unknown",
                "req": req_body,
                "resp": resp_body,
                "reason": entry.get("details")
            }
        )
        db.commit()
        
        # Send Syslog
        try:
            syslog_host = db.execute(text("SELECT setting_value FROM global_settings WHERE setting_key = 'syslog_host'")).fetchone()
            if syslog_host and syslog_host[0]:
                syslog_port = db.execute(text("SELECT setting_value FROM global_settings WHERE setting_key = 'syslog_port'")).fetchone()
                s_port = int(syslog_port[0]) if syslog_port and syslog_port[0] else 514
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                msg = f"<13>{datetime.utcnow().strftime('%b %d %H:%M:%S')} luminawaf-waf: {json.dumps(entry)}"
                sock.sendto(msg.encode('utf-8'), (syslog_host[0], s_port))
                sock.close()
        except:
            pass
            
        # Handle 429 Blacklisting and DDoS Disable
        if status_code == 429:
            ip = entry.get("client_ip")
            if ip:
                ttl_row = db.execute(text("SELECT setting_value FROM global_settings WHERE setting_key = 'ddos_blacklist_ttl_minutes'")).fetchone()
                try:
                    ttl = int(ttl_row[0]) if ttl_row and ttl_row[0] else 10
                except:
                    ttl = 10
                
                expires_at = datetime.utcnow() + timedelta(minutes=ttl)
                import uuid
                
                db.execute(text("""
                INSERT INTO ip_rules (id, ip_address, rule_type, notes, created_at, expires_at)
                VALUES (:id, :ip, 'Blacklist', 'Auto-blocked DDoS (Rate Limit)', :now, :expires_at)
                ON CONFLICT (ip_address) DO UPDATE SET expires_at = EXCLUDED.expires_at
                """), {"id": str(uuid.uuid4()), "ip": ip, "now": datetime.utcnow(), "expires_at": expires_at})
                db.commit()
                
                # Tell backend to regenerate LDS because a new IP rule was added
                import requests
                try: requests.post("http://waf-backend:8000/api/internal/trigger-update", timeout=1)
                except: pass
                
                # Check for DDoS Virtual Server Toggling
                three_mins_ago = datetime.utcnow() - timedelta(minutes=3)
                cnt_row = db.execute(text("SELECT count(distinct client_ip) FROM access_logs WHERE vs_id = :vs_id AND status_code = 429 AND timestamp > :start_time"), {
                    "vs_id": vs_id, "start_time": three_mins_ago
                }).fetchone()
                
                if cnt_row and cnt_row[0] >= 5:
                    # Target has > 5 distinct IPs hit 429 threshold in 3 minutes -> DDoS!
                    # Disable it if not already offline
                    vs_active = db.execute(text("SELECT active FROM virtual_servers WHERE id = :v"), {"v": vs_id}).fetchone()
                    if vs_active and vs_active[0] == True:
                        db.execute(text("UPDATE virtual_servers SET active = false WHERE id = :v"), {"v": vs_id})
                        db.commit()
                        try:
                            requests.post("http://waf-backend:8000/api/internal/trigger-update", timeout=1)
                            requests.post("http://waf-backend:8000/api/internal/send-email", json={"vs_id": vs_id}, timeout=3)
                        except: pass

def report_worker():
    while True:
        try:
            with SessionLocal() as db:
                # Check for subscriptions
                subs = db.execute(text("""
                    SELECT rs.id, rs.user_id, rs.frequency, rs.last_sent, u.email 
                    FROM report_subscriptions rs
                    JOIN users u ON rs.user_id = u.id
                    WHERE u.email IS NOT NULL
                """)).fetchall()

                for sub_id, user_id, freq, last_sent, user_email in subs:
                    # Check if it's time to send
                    now = datetime.utcnow()
                    should_send = False
                    if not last_sent:
                        should_send = True
                    else:
                        if freq == 'daily' and now - last_sent > timedelta(days=1):
                            should_send = True
                        elif freq == 'weekly' and now - last_sent > timedelta(days=7):
                            should_send = True
                    
                    if should_send:
                        # Generate Report Data
                        days = 1 if freq == 'daily' else 7
                        start_time = now - timedelta(days=days)
                        
                        total_req = db.execute(text("SELECT count(*) FROM access_logs WHERE timestamp > :s"), {"s": start_time}).scalar()
                        total_blocked = db.execute(text("SELECT count(*) FROM access_logs WHERE timestamp > :s AND status_code IN (403, 406, 429)"), {"s": start_time}).scalar()
                        
                        top_ips = db.execute(text("""
                            SELECT client_ip, count(*) as c 
                            FROM access_logs 
                            WHERE timestamp > :s 
                            GROUP BY client_ip 
                            ORDER BY c DESC LIMIT 5
                        """), {"s": start_time}).fetchall()
                        
                        top_ips_html = "".join([f"<tr><td>{ip}</td><td>{c}</td></tr>" for ip, c in top_ips])
                        
                        html_content = f"""
                        <html>
                        <body style="background-color: #0f172a; color: #f8fafc; font-family: sans-serif; padding: 40px;">
                            <div style="max-width: 600px; margin: 0 auto; background-color: #1e293b; border: 1px solid #334155; border-radius: 20px; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);">
                                <div style="background-color: #4f46e5; padding: 30px; text-align: center;">
                                    <h1 style="margin: 0; font-size: 24px; letter-spacing: 2px;">LUMINAWAF SECURITY DIGEST</h1>
                                    <p style="margin: 5px 0 0; opacity: 0.8; font-size: 12px; text-transform: uppercase;">{freq.capitalize()} Infrastructure Report</p>
                                </div>
                                <div style="padding: 30px;">
                                    <div style="display: flex; gap: 20px; margin-bottom: 30px;">
                                        <div style="flex: 1; background-color: #0f172a; padding: 20px; border-radius: 15px; text-align: center;">
                                            <div style="font-size: 24px; font-weight: bold; color: #38bdf8;">{total_req}</div>
                                            <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase;">Total Requests</div>
                                        </div>
                                        <div style="flex: 1; background-color: #0f172a; padding: 20px; border-radius: 15px; text-align: center;">
                                            <div style="font-size: 24px; font-weight: bold; color: #f87171;">{total_blocked}</div>
                                            <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase;">Blocked</div>
                                        </div>
                                    </div>
                                    <h3 style="font-size: 14px; text-transform: uppercase; color: #94a3b8; margin-bottom: 15px;">Top Attacking Sources</h3>
                                    <table style="width: 100%; border-collapse: collapse;">
                                        <tr style="border-bottom: 1px solid #334155; color: #94a3b8; font-size: 12px; text-align: left;">
                                            <th style="padding: 10px;">Source IP Address</th>
                                            <th style="padding: 10px; text-align: right;">Intercepts</th>
                                        </tr>
                                        {top_ips_html}
                                    </table>
                                    <div style="margin-top: 40px; text-align: center;">
                                        <a href="http://localhost:5173" style="background-color: #4f46e5; color: white; padding: 12px 30px; border-radius: 10px; text-decoration: none; font-weight: bold; font-size: 14px;">VIEW FULL DASHBOARD</a>
                                    </div>
                                </div>
                            </div>
                        </body>
                        </html>
                        """
                        
                        # Send email via backend
                        try:
                            import requests
                            requests.post("http://waf-backend:8000/api/internal/send-report", json={
                                "user_email": user_email,
                                "frequency": freq,
                                "html_content": html_content
                            }, timeout=10)
                            
                            # Update last_sent
                            db.execute(text("UPDATE report_subscriptions SET last_sent = :now WHERE id = :id"), {"now": now, "id": sub_id})
                            db.commit()
                        except Exception as e:
                            print(f"[ReportWorker] Failed to send report: {e}")

        except Exception as e:
            print(f"[ReportWorker] Error: {e}")
            traceback.print_exc()

        time.sleep(3600) # Check every hour

if __name__ == "__main__":
    time.sleep(5) # Wait for DB to be up
    
    # Start retention worker thread
    t = threading.Thread(target=retention_worker, daemon=True)
    t.start()
    
    # Start report worker thread
    t_report = threading.Thread(target=report_worker, daemon=True)
    t_report.start()
    
    # Start tailing logs
    tail_logs()
