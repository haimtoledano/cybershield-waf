import asyncio
import socket
import datetime
from sqlalchemy.orm import Session
import database
import schemas
import urllib.parse

async def check_target_health(target: str) -> bool:
    """
    Checks if a target is reachable via TCP.
    """
    try:
        # Normalize target
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            if ":" in target:
                host, port = target.split(":")
                port = int(port)
            else:
                host = target
                port = 80
        
        # Use asyncio.open_connection for non-blocking check
        conn = asyncio.open_connection(host, port)
        try:
            reader, writer = await asyncio.wait_for(conn, timeout=3.0)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    except Exception:
        return False

async def health_checker_loop():
    """
    Background loop that checks all virtual servers every 30 seconds.
    """
    print("Starting Health Checker Background Loop...")
    while True:
        try:
            with database.SessionLocal() as db:
                servers = db.query(database.VirtualServer).all()
                for server in servers:
                    is_online = await check_target_health(server.backend_target)
                    
                    # Update DB if status changed or just update last_check
                    server.is_online = is_online
                    server.last_check = datetime.datetime.utcnow()
                    
                db.commit()
        except Exception as e:
            print(f"Health Checker Error: {e}")
        
        await asyncio.sleep(30)
