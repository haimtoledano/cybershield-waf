import urllib.request
import json
import threading

def run_auto_discovery(vs_id: str, backend_target: str, db_add_profile_callback):
    """
    Runs a passive scan of the target to fingerprint and add rulesets asynchronously.
    """
    def scan_task():
        try:
            target_url = f"http://{backend_target}"
            if not backend_target.startswith("http"):
                target_url = f"http://{backend_target}"
                
            req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) LuminaWAF/1.0'})
            try:
                with urllib.request.urlopen(req, timeout=3.0) as response:
                    headers = response.info()
                    body = response.read().decode('utf-8', errors='ignore').lower()
            except Exception:
                # If target is down or rejecting connection, return safely.
                return
                
            headers_str = str(headers).lower()
            
            detected = []
            
            # Application Servers
            if "nginx" in headers_str:
                detected.append("Nginx")
            if "apache" in headers_str:
                detected.append("Apache")
                
            # Backend Languages
            if "php" in headers_str or ".php" in body or "x-powered-by: php" in headers_str:
                detected.append("PHP-Engine")
            if "node" in headers_str or "express" in headers_str:
                detected.append("NodeJS")
                
            # CMS
            if "wordpress" in body or "wp-content" in body or "wp-includes" in body:
                detected.append("WordPress")
            if "nextcloud" in body or "owncloud" in body:
                detected.append("Nextcloud")
            if "drupal" in body:
                detected.append("Drupal")
            if "joomla" in body:
                detected.append("Joomla")
                
            if detected:
                db_add_profile_callback(vs_id, detected)
                
        except Exception as e:
            # Silently fail auto-discovery in case of unhandled network errors
            pass

    thread = threading.Thread(target=scan_task)
    thread.daemon = True
    thread.start()
