from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import database
import schemas
import yaml
import os
import json
import scanner

# Create tables
database.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="WAF Control Plane API")

import auth
import users_router
import ip_rules_router

app.include_router(auth.auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(users_router.users_router, prefix="/api/users", tags=["users"])
app.include_router(ip_rules_router.ip_rules_router)

@app.on_event("startup")
def startup_event():
    with database.SessionLocal() as session:
        if session.query(database.User).count() == 0:
            superadmin = database.User(
                username='superadmin',
                hashed_password=auth.get_password_hash('CyberShield2026!'),
                role=database.UserRole.admin,
                mfa_enabled=False
            )
            session.add(superadmin)
            session.commit()
            print("Superadmin user generated automatically.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def generate_cds(servers):
    import urllib.parse
    cds = {"resources": []}
    for server in servers:
        # Normalize target to ensure urlparse works
        target = server.backend_target if "://" in server.backend_target else f"http://{server.backend_target}"
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        cluster = {
            "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
            "name": server.name,
            "connect_timeout": "0.25s",
            "type": "STRICT_DNS",
            "load_assignment": {
                "cluster_name": server.name,
                "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {"socket_address": {
                    "address": host, 
                    "port_value": port
                }}}}]}]
            }
        }
        cds["resources"].append(cluster)
    return yaml.dump(cds, sort_keys=False)

def generate_lds(servers, blacklisted_ips=None, whitelisted_ips=None):
    if blacklisted_ips is None: blacklisted_ips = []
    if whitelisted_ips is None: whitelisted_ips = []
    lds = {"resources": []}
    for server in servers:
        request_headers = [
            {"header": {"key": h.header_key, "value": h.header_value}, "append_action": "OVERWRITE_IF_EXISTS_OR_ADD"}
            for h in getattr(server, "headers", []) if h.direction == database.HeaderDirection.Request
        ]
        
        response_headers = [
            {"header": {"key": h.header_key, "value": h.header_value}, "append_action": "OVERWRITE_IF_EXISTS_OR_ADD"}
            for h in getattr(server, "headers", []) if h.direction == database.HeaderDirection.Response
        ]
        
        route_config = {"match": {"prefix": "/"}, "route": {"cluster": server.name}}
        if request_headers:
            route_config["request_headers_to_add"] = request_headers
        if response_headers:
            route_config["response_headers_to_add"] = response_headers

        vhost = {
            "name": server.name,
            "domains": ["*"],
            "routes": [route_config]
        }
        
        if getattr(server, "rate_limit_enabled", False):
            vhost["rate_limits"] = [{"actions": [{"remote_address": {}}]}]

        listener = {
            "@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
            "name": f"listener_{server.name}",
            "address": {"socket_address": {"address": "0.0.0.0", "port_value": server.ingress_port}},
            "filter_chains": [{
                "filters": [{
                    "name": "envoy.filters.network.http_connection_manager",
                    "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                        "stat_prefix": f"listener_{server.name}",
                        "route_config": {
                            "name": "local_route",
                            "virtual_hosts": [vhost]
                        },
                        "use_remote_address": True,
                        "forward_client_cert_details": "SANITIZE_SET",
                        "local_reply_config": {
                            "mappers": [
                                {
                                    "filter": {
                                        "status_code_filter": {
                                            "comparison": {
                                                "op": "GE",
                                                "value": {"default_value": 400, "runtime_key": "dummy"}
                                            }
                                        }
                                    },
                                    "body": {
                                        "inline_string": "<html><head><meta charset=\"UTF-8\"><title>CyberShield Gateway Blocked</title><style>body{background:#0d1117;color:#ff4d4d;font-family:monospace;padding:50px;text-align:center;}h1{font-size:3em;}div{margin-top:20px;padding:20px;border:1px solid #ff4d4d;display:inline-block;}</style></head><body><h1>🛡️ CyberShield Gateway</h1><div>Error: Request Blocked or Upstream Unavailable</div></body></html>"
                                    },
                                    "headers_to_add": [{"header": {"key": "content-type", "value": "text/html; charset=UTF-8"}, "append_action": "OVERWRITE_IF_EXISTS_OR_ADD"}]
                                }
                            ]
                        },
                        "access_log": [{
                            "name": "envoy.access_loggers.file",
                            "typed_config": {
                                "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
                                "path": "/etc/envoy/dynamic/access.log",
                                "log_format": {
                                    "json_format": {
                                        "time": "%START_TIME%",
                                        "method": "%REQ(:METHOD)%",
                                        "path": "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
                                        "protocol": "%PROTOCOL%",
                                        "status": "%RESPONSE_CODE%",
                                        "details": "%RESPONSE_CODE_DETAILS%",
                                        "duration": "%DURATION%",
                                        "bytes_sent": "%BYTES_SENT%",
                                        "bytes_received": "%BYTES_RECEIVED%",
                                        "client_ip": "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%",
                                        "user_agent": "%REQ(USER-AGENT)%",
                                        "server": server.name,
                                        "req_body": "%DYNAMIC_METADATA(envoy.filters.http.lua:req_body)%",
                                        "resp_body": "%DYNAMIC_METADATA(envoy.filters.http.lua:resp_body)%"
                                    }
                                }
                            }
                        }],
                        "http_filters": []
                    }
                }]
            }]
        }

        http_filters = []
        
        if blacklisted_ips:
            principals = [{"direct_remote_ip": {"address_prefix": ip, "prefix_len": 32}} for ip in blacklisted_ips]
            http_filters.append({
                "name": "envoy.filters.http.rbac",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC",
                    "rules": {
                        "action": "DENY",
                        "policies": {
                            "global_blacklist": {
                                "permissions": [{"any": True}],
                                "principals": principals
                            }
                        }
                    }
                }
            })

        http_filters.append({
            "name": "envoy.filters.http.buffer",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer",
                "max_request_bytes": 1048576
            }
        })
        
        listener["filter_chains"][0]["filters"][0]["typed_config"]["http_filters"] = http_filters
        
        if server.waf_mode != 'Disabled':
            coraza_config = generate_coraza_config(server, whitelisted_ips)
            listener["filter_chains"][0]["filters"][0]["typed_config"]["http_filters"].append({
                "name": "envoy.filters.http.wasm",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
                    "config": {
                        "name": "coraza-filter",
                        "root_id": "",
                        "configuration": {
                            "@type": "type.googleapis.com/google.protobuf.StringValue",
                            "value": coraza_config
                        },
                        "vm_config": {
                            "runtime": "envoy.wasm.runtime.v8",
                            "vm_id": f"coraza-vm-{server.name}",
                            "code": {
                                "local": {
                                    "filename": "/etc/envoy/coraza-proxy-wasm.wasm"
                                }
                            }
                        }
                    }
                }
            })
            
        listener["filter_chains"][0]["filters"][0]["typed_config"]["http_filters"].extend([
            {
                "name": "envoy.filters.http.lua",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
                    "default_source_code": {
                        "inline_string": generate_waf_lua(server)
                    }
                }
            },
            {
                "name": "envoy.filters.http.router", 
                "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}
            }
        ])
        
        lds["resources"].append(listener)
    return yaml.dump(lds, sort_keys=False)

# Cache for loaded CRS rules to avoid repeated I/O
_crs_rules_cache = []

def get_crs_rules():
    global _crs_rules_cache
    if _crs_rules_cache:
        return _crs_rules_cache
    
    import glob
    import os
    
    skip_files = [
        "REQUEST-913-SCANNER-DETECTION.conf",
        "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
        "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
        "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
        "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
        "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
        "RESPONSE-951-DATA-LEAKAGES-SQL.conf",
        "RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
        "RESPONSE-953-DATA-LEAKAGES-PHP.conf",
        "RESPONSE-954-DATA-LEAKAGES-IIS.conf",
        "RESPONSE-955-WEB-SHELLS.conf"
    ]
    
    loaded = []
    # Load base CRS setup
    crs_setup_path = "/app/crs/crs-setup.conf.example"
    if os.path.exists(crs_setup_path):
        with open(crs_setup_path, "r", encoding="utf-8") as f:
            loaded.append(f.read())
            
    # Load all rules in order
    rules_path = "/app/crs/rules/*.conf"
    for file in sorted(glob.glob(rules_path)):
        if os.path.basename(file) in skip_files:
            continue
        with open(file, "r", encoding="utf-8") as f:
            loaded.append(f.read())
            
    _crs_rules_cache = loaded
    return _crs_rules_cache

def generate_coraza_config(server, whitelisted_ips=None):
    if whitelisted_ips is None: whitelisted_ips = []
    engine = 'DetectionOnly' if server.waf_mode == 'Logging' else 'On'
    directives = [
        "SecRuleEngine " + engine
    ]
    
    # Inject Global Whitelist
    for idx, ip in enumerate(whitelisted_ips):
        directives.append(f'SecRule REMOTE_ADDR "@ipMatch {ip}" "id:1000{idx},phase:1,nolog,allow,ctl:ruleEngine=Off,msg:\'IP Whitelist Bypass\'"')

    
    # Append all embedded CRS Rules inline
    directives.extend(get_crs_rules())
    
    # CMS / Tech Tuning via CRS Exclusion variables
    active_profiles = [p.profile_name for p in server.profiles]
    
    if "WordPress" in active_profiles:
        directives.append("SecAction \"id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1\"")
    if "Nextcloud" in active_profiles:
        directives.append("SecAction \"id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_nextcloud=1\"")
    if "Drupal" in active_profiles:
        directives.append("SecAction \"id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_drupal=1\"")
    if "Joomla" in active_profiles:
        directives.append("SecAction \"id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_joomla=1\"")
    
    # Determine Rule Categories mapping
    # OWASP CRS uses tags like 'attack-sqli', 'attack-xss', 'attack-rce', etc.
    tag_mapping = {
        "Protocol-Enforcement": "protocol-enforcement",
        "Protocol-Attack": "protocol-attack",
        "LFI": "attack-lfi",
        "RFI": "attack-rfi",
        "RCE": "attack-rce",
        "PHP-Injection": "language-php",
        "XSS": "attack-xss",
        "SQLi": "attack-sqli",
        "Session-Fixation": "attack-fixation",
        "Java-Injection": "language-java",
        "Scanner-Detection": "scan-tools", # Or scanners
        "Data-Leakage": "data-leakage"
    }
    
    for profile_name, crs_tag in tag_mapping.items():
        if profile_name not in active_profiles:
            # If the user toggled it OFF, we ask Coraza to remove all rules with this tag
            directives.append(f"SecRuleRemoveByTag \"{crs_tag}\"")
    
    # Custom path exclusions from DB
    if server.exclusions:
        ids_start = 100000
        for exc in server.exclusions:
            directives.append(f"SecRule REQUEST_URI \"@contains {exc.path_pattern}\" \"id:{ids_start},phase:1,pass,nolog,ctl:ruleEngine=Off\"")
            ids_start += 1
            
    config = {
        "directives_map": {"default": directives},
        "default_directives": "default"
    }
    return json.dumps(config)

def generate_waf_lua(server):
    lua_script = "-- Payload Logger & Rate Limiter Module\n"
    lua_script += "function envoy_on_request(request_handle)\n"
    
    if getattr(server, "rate_limit_enabled", False):
        lua_script += f"  local rpm_limit = {server.rate_limit_rpm}\n"
        lua_script += "  local ip_full = request_handle:streamInfo():downstreamDirectRemoteAddress()\n"
        lua_script += "  local ip = string.match(ip_full, '^([^:]+)') or ip_full\n"
        lua_script += "  if not _G.rl_counter then _G.rl_counter = {} end\n"
        lua_script += "  if not _G.rl_reset then _G.rl_reset = {} end\n"
        # Since os.time() is not available explicitly in some proxy-wasm lua runtimes, 
        # we can use Envoy's timestamp in milliseconds!
        lua_script += "  local now = request_handle:timestampMillis() / 1000\n"
        lua_script += "  if not _G.rl_reset[ip] or now > _G.rl_reset[ip] then\n"
        lua_script += "    _G.rl_counter[ip] = 0\n"
        lua_script += "    _G.rl_reset[ip] = now + 60\n"
        lua_script += "  end\n"
        lua_script += "  _G.rl_counter[ip] = _G.rl_counter[ip] + 1\n"
        lua_script += "  if _G.rl_counter[ip] > rpm_limit then\n"
        lua_script += "     request_handle:respond({[':status'] = '429', ['Content-Type'] = 'text/plain'}, 'Rate Limit Exceeded')\n"
        lua_script += "     return\n"
        lua_script += "  end\n"

    lua_script += "  local req_body = request_handle:body()\n"
    lua_script += "  if req_body then\n"
    lua_script += "    local body_bytes = req_body:getBytes(0, req_body:length())\n"
    lua_script += "    if string.len(body_bytes) > 10240 then body_bytes = string.sub(body_bytes, 1, 10240) end\n"
    lua_script += "    request_handle:streamInfo():dynamicMetadata():set('envoy.filters.http.lua', 'req_body', body_bytes)\n"
    lua_script += "  end\n"
    lua_script += "end\n\n"
    
    # Intercept upstream fast fail 404/500 to show our page
    lua_script += "function envoy_on_response(response_handle)\n"
    lua_script += "  local resp_body = response_handle:body()\n"
    lua_script += "  if resp_body then\n"
    lua_script += "    local body_bytes = resp_body:getBytes(0, resp_body:length())\n"
    lua_script += "    if string.len(body_bytes) > 10240 then body_bytes = string.sub(body_bytes, 1, 10240) end\n"
    lua_script += "    response_handle:streamInfo():dynamicMetadata():set('envoy.filters.http.lua', 'resp_body', body_bytes)\n"
    lua_script += "  end\n"
    lua_script += "  \n"
    lua_script += "  local status = tonumber(response_handle:headers():get(':status'))\n"
    lua_script += "  if status and status >= 400 and status <= 599 then\n"
    lua_script += "    local block_html_res = [[<html><head><meta charset=\"UTF-8\"><title>CyberShield Blocked</title><style>body{background:#0d1117;color:#ff4d4d;font-family:monospace;padding:50px;text-align:center;}h1{font-size:3em;}div{margin-top:20px;padding:20px;border:1px solid #ff4d4d;display:inline-block;}</style></head><body><h1>🛡️ CyberShield Gateway</h1><div>Error: Upstream returned ]] .. tostring(status) .. [[</div></body></html>]]\n"
    # Note: Envoy Lua filter currently cannot completely replace an upstream response body if it was already generated by the router, 
    # but we can set a header to indicate we intercepted it. Since full body replacement in envoy_on_response requires body chunks iteration,
    # we will rely on WAF blocking natively on request.
    lua_script += "    response_handle:headers():add('X-CyberShield-Intercept', 'true')\n"
    lua_script += "  end\n"
    lua_script += "end\n"

    return lua_script

def trigger_envoy_update(db: Session):
    try:
        servers = db.query(database.VirtualServer).all()
        blacklisted_ips = [r.ip_address for r in db.query(database.IPRule).filter(database.IPRule.rule_type == database.IPRuleType.Blacklist).all()]
        whitelisted_ips = [r.ip_address for r in db.query(database.IPRule).filter(database.IPRule.rule_type == database.IPRuleType.Whitelist).all()]
        
        cds_path = "/app/envoy-dynamic/cds.yaml"
        lds_path = "/app/envoy-dynamic/lds.yaml"

        os.makedirs(os.path.dirname(cds_path), exist_ok=True)
        cds_temp = cds_path + ".tmp"
        lds_temp = lds_path + ".tmp"
        
        with open(cds_temp, 'w') as f:
            f.write(generate_cds(servers))
        os.replace(cds_temp, cds_path)
            
        with open(lds_temp, 'w') as f:
            f.write(generate_lds(servers, blacklisted_ips, whitelisted_ips))
        os.replace(lds_temp, lds_path)
            
        print("Envoy configuration successfully pushed via file-based xDS!")
    except Exception as e:
        print(f"Failed to push Envoy configuration: {e}")

@app.post("/api/virtual-servers/", response_model=schemas.VirtualServerWithExclusions, status_code=status.HTTP_201_CREATED)
def create_virtual_server(virtual_server: schemas.VirtualServerCreate, db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.require_admin)):
    vs_data = virtual_server.model_dump(exclude={'profiles'})
    db_virtual_server = database.VirtualServer(**vs_data)
    db.add(db_virtual_server)
    
    # Initialize basic strict subsets
    default_rules = [
        "Protocol-Enforcement", "Protocol-Attack", "LFI", "RFI",
        "RCE", "PHP-Injection", "XSS", "SQLi", "Session-Fixation", 
        "Java-Injection", "Data-Leakage"
    ]
    
    for rule in default_rules:
        db.add(database.VirtualServerProfile(virtual_server=db_virtual_server, profile_name=rule))
        
    for profile_name in virtual_server.profiles:
        db.add(database.VirtualServerProfile(virtual_server=db_virtual_server, profile_name=profile_name))
        
    db.commit()
    db.refresh(db_virtual_server)
    
    def add_auto_profiles(vs_id, profiles):
        # We need a new session for the background thread
        with database.SessionLocal() as bg_db:
            existing = [p.profile_name for p in bg_db.query(database.VirtualServerProfile).filter(database.VirtualServerProfile.vs_id == vs_id).all()]
            added = False
            for p in profiles:
                if p not in existing:
                    bg_db.add(database.VirtualServerProfile(vs_id=vs_id, profile_name=p))
                    added = True
            if added:
                bg_db.commit()
                trigger_envoy_update(bg_db)
                
    scanner.run_auto_discovery(db_virtual_server.id, db_virtual_server.backend_target, add_auto_profiles)
    
    trigger_envoy_update(db)
    return db_virtual_server

@app.get("/api/virtual-servers/", response_model=list[schemas.VirtualServerWithExclusions], status_code=status.HTTP_200_OK)
def list_virtual_servers(db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.get_current_user)):
    return db.query(database.VirtualServer).all()

@app.get("/api/virtual-servers/{vs_id}", response_model=schemas.VirtualServerWithExclusions, status_code=status.HTTP_200_OK)
def read_virtual_server(vs_id: str, db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.get_current_user)):
    db_virtual_server = db.query(database.VirtualServer).filter(database.VirtualServer.id == vs_id).first()
    if not db_virtual_server:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Virtual Server not found")
    return db_virtual_server

@app.put("/api/virtual-servers/{vs_id}", response_model=schemas.VirtualServerWithExclusions, status_code=status.HTTP_200_OK)
def update_virtual_server(vs_id: str, virtual_server_update: schemas.VirtualServerUpdate, db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.require_admin)):
    db_virtual_server = db.query(database.VirtualServer).filter(database.VirtualServer.id == vs_id).first()
    if not db_virtual_server:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Virtual Server not found")
    
    update_data = virtual_server_update.model_dump(exclude_unset=True)
    profiles_data = update_data.pop('profiles', None)
    
    for key, value in update_data.items():
        setattr(db_virtual_server, key, value)
        
    if profiles_data is not None:
        db.query(database.VirtualServerProfile).filter(database.VirtualServerProfile.vs_id == vs_id).delete()
        for profile_name in profiles_data:
            db.add(database.VirtualServerProfile(vs_id=vs_id, profile_name=profile_name))
            
    db.commit()
    db.refresh(db_virtual_server)
    trigger_envoy_update(db)
    return db_virtual_server

@app.delete("/api/virtual-servers/{vs_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_virtual_server(vs_id: str, db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.require_admin)):
    db_virtual_server = db.query(database.VirtualServer).filter(database.VirtualServer.id == vs_id).first()
    if not db_virtual_server:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Virtual Server not found")
    
    db.delete(db_virtual_server)
    db.commit()
    trigger_envoy_update(db)
    return None

import json

from typing import Optional

@app.get("/api/logs")
def get_logs(
    vs_id: Optional[str] = None, 
    status_class: Optional[str] = None, 
    search: Optional[str] = None,
    limit: int = 100,
    page: int = 1,
    db: Session = Depends(database.get_db),
    current_user: database.User = Depends(auth.get_current_user)
):
    query = db.query(database.AccessLog)
    
    if vs_id:
        query = query.filter(database.AccessLog.vs_id == vs_id)
        
    if status_class:
        if status_class == "2xx":
            query = query.filter(database.AccessLog.status_code >= 200, database.AccessLog.status_code < 300)
        elif status_class == "4xx":
            query = query.filter(database.AccessLog.status_code >= 400, database.AccessLog.status_code < 500)
        elif status_class == "5xx":
            query = query.filter(database.AccessLog.status_code >= 500)
        elif status_class == "blocked":
            query = query.filter(database.AccessLog.status_code == 403)
            
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (database.AccessLog.path.ilike(search_term)) | 
            (database.AccessLog.user_agent.ilike(search_term)) |
            (database.AccessLog.req_payload.ilike(search_term))
        )
        
    total_count = query.count()
    
    skip = (page - 1) * limit
    logs = query.order_by(database.AccessLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    # Format to match existing JSON structure for frontend
    formatted_logs = []
    for log in logs:
        # Resolve server name from vs_id (just quick mapping, theoretically we'd join)
        server = db.query(database.VirtualServer).filter(database.VirtualServer.id == log.vs_id).first()
        server_name = server.name if server else log.vs_id
        
        formatted_logs.append({
            "id": log.id, # useful for uniquely identifying
            "time": log.timestamp.isoformat() + "Z",
            "method": log.method,
            "path": log.path,
            "status": log.status_code,
            "client_ip": log.client_ip,
            "user_agent": log.user_agent,
            "server": server_name,
            "vs_id": log.vs_id,
            "req_body": log.req_payload,
            "resp_body": log.resp_payload,
            "block_reason": log.block_reason
        })
        
    return {"total": total_count, "logs": formatted_logs}

@app.post("/api/exclusions", response_model=schemas.RuleExclusionRead)
def create_exclusion(exclusion: schemas.RuleExclusionCreate, vs_id: str, db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.require_admin)):
    db_exc = database.RuleExclusion(**exclusion.model_dump(), vs_id=vs_id)
    db.add(db_exc)
    db.commit()
    db.refresh(db_exc)
    trigger_envoy_update(db)
    return db_exc

@app.delete("/api/exclusions/{exc_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_exclusion(exc_id: str, db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.require_admin)):
    db_exc = db.query(database.RuleExclusion).filter(database.RuleExclusion.id == exc_id).first()
    if db_exc:
        db.delete(db_exc)
        db.commit()
        trigger_envoy_update(db)
    return None

@app.post("/api/headers", response_model=schemas.CustomHeaderRead)
def create_header(header: schemas.CustomHeaderCreate, vs_id: str, db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.require_admin)):
    db_header = database.CustomHeader(**header.model_dump(), vs_id=vs_id)
    db.add(db_header)
    db.commit()
    db.refresh(db_header)
    trigger_envoy_update(db)
    return db_header

@app.delete("/api/headers/{header_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_header(header_id: str, db: Session = Depends(database.get_db), current_user: database.User = Depends(auth.require_admin)):
    db_header = db.query(database.CustomHeader).filter(database.CustomHeader.id == header_id).first()
    if db_header:
        db.delete(db_header)
        db.commit()
        trigger_envoy_update(db)
    return None
