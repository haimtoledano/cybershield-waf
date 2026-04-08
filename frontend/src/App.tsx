import React, { useState, useEffect } from 'react';
import { Server, Activity, PlusCircle, X, Trash2, Shield, ShieldCheck, Terminal, ShieldAlert, ChevronDown, ChevronUp, AlertOctagon, LayoutTemplate, Cloud, Code, User, Users, Database, LogOut } from 'lucide-react';
import { LoginView, MFASetupView } from './AuthViews';
import UsersTab from './UsersTab';

const ruleCategories = [
  { id: 'Protocol-Enforcement', label: 'Protocol Enforcement', desc: 'Enforces strict HTTP protocol standards.', icon: ShieldCheck },
  { id: 'Protocol-Attack', label: 'Protocol Attack', desc: 'Blocks HTTP Smuggling and Splitting.', icon: ShieldAlert },
  { id: 'LFI', label: 'Local File Inclusion', desc: 'Blocks traversal and /etc/passwd reads.', icon: LayoutTemplate },
  { id: 'RFI', label: 'Remote File Inclusion', desc: 'Prevents fetching remote payloads.', icon: Cloud },
  { id: 'RCE', label: 'Remote Code Execution', desc: 'Blocks shell commands (e.g. bash, wget).', icon: Terminal },
  { id: 'PHP-Injection', label: 'PHP Injection', desc: 'Secures against PHP evaluation.', icon: Code },
  { id: 'XSS', label: 'Cross-Site Scripting', desc: 'Prevents script and JS injection.', icon: ShieldAlert },
  { id: 'SQLi', label: 'SQL Injection', desc: 'Blocks SELECT, UNION and logic flaws.', icon: Database },
  { id: 'Session-Fixation', label: 'Session Fixation', desc: 'Prevents session hijacking.', icon: User },
  { id: 'Java-Injection', label: 'Java/Struts Injection', desc: 'Blocks Log4Shell & Struts traits.', icon: Code },
  { id: 'Scanner-Detection', label: 'Scanner Detection', desc: 'Blocks bots like Nikto and Nmap.', icon: AlertOctagon },
  { id: 'Data-Leakage', label: 'Data Leakage', desc: 'Prevents backend error exposure.', icon: ShieldCheck }
];

const appCategories = [
  { id: 'WordPress', label: 'WordPress Core', desc: 'Heuristics for WP paths.', icon: LayoutTemplate },
  { id: 'Nextcloud', label: 'Nextcloud/OwnCloud', desc: 'Nextcloud specific exclusions.', icon: Cloud },
  { id: 'Drupal', label: 'Drupal CMS', desc: 'Drupal routing exclusions.', icon: LayoutTemplate },
  { id: 'Joomla', label: 'Joomla CMS', desc: 'Joomla administration exclusions.', icon: LayoutTemplate },
  { id: 'Nginx', label: 'Nginx Server', desc: 'Nginx response optimizations.', icon: Server },
  { id: 'Apache', label: 'Apache Server', desc: 'Apache specific signatures.', icon: Server },
  { id: 'NodeJS', label: 'Node.js Backend', desc: 'Express and Node optimizations.', icon: Code },
  { id: 'PHP-Engine', label: 'PHP Engine', desc: 'PHP specific backend parsing.', icon: Code }
];

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'servers'|'logs'|'users'>('servers');
  const [authToken, setAuthToken] = useState<string | null>(localStorage.getItem('waf_token'));
  const [currentUser, setCurrentUser] = useState<any>(JSON.parse(localStorage.getItem('waf_user') || 'null'));
  const [mfaSetupUri, setMfaSetupUri] = useState<string | null>(null);
  const [loginError, setLoginError] = useState<string|null>(null);
  const [needsMfaCode, setNeedsMfaCode] = useState<boolean>(false);
  const [servers, setServers] = useState<any[]>([]);
  const [logs, setLogs] = useState<any[]>([]);
  
  // Pagination State
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [logsLimit, setLogsLimit] = useState<number>(100);
  const [totalLogs, setTotalLogs] = useState<number>(0);
  
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState(false);
  const [activeServer, setActiveServer] = useState<any>(null);

  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const [filterServer, setFilterServer] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchTxt, setSearchTxt] = useState<string>('');

  const [newServer, setNewServer] = useState({
    name: '', ingress_port: 0, backend_target: '', waf_mode: 'Disabled', log_retention_days: 7, profiles: []
  });
  const [activeSettingsTab, setActiveSettingsTab] = useState<'rules' | 'apps' | 'exclusions' | 'headers' | 'ddos'>('rules');
  const [newHeader, setNewHeader] = useState({ direction: 'Response', header_key: '', header_value: '' });

  const fetchWithAuth = async (url: string, options: any = {}) => {
    const headers = { ...options.headers, 'Authorization': `Bearer ${authToken}` };
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      handleLogout();
    }
    return res;
  };

  const handleLogout = () => {
      setAuthToken(null);
      setCurrentUser(null);
      setMfaSetupUri(null);
      localStorage.removeItem('waf_token');
      localStorage.removeItem('waf_user');
  };

  const handleLogin = async (user: string, pass: string, mfaCode?: string) => {
    try {
      setLoginError(null);
      const res = await fetch('http://localhost:8555/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass, mfa_code: mfaCode })
      });
      const data = await res.json();
      if (!res.ok) {
         if (data.detail === "MFA_REQUIRED") {
             setNeedsMfaCode(true);
             setLoginError("Please enter your 6-digit MFA Code.");
             return;
         }
         throw new Error(data.detail || "Login failed");
      }
      
      setAuthToken(data.access_token);
      setCurrentUser(data.user);
      localStorage.setItem('waf_token', data.access_token);
      localStorage.setItem('waf_user', JSON.stringify(data.user));

      if (data.mfa_setup_needed) {
         const mfaRes = await fetch('http://localhost:8555/api/auth/mfa/setup', {
            headers: { 'Authorization': `Bearer ${data.access_token}` }
         });
         const mfaData = await mfaRes.json();
         setMfaSetupUri(mfaData.uri);
      }
    } catch(e: any) {
      setLoginError(e.message);
    }
  };

  const handleMfaVerify = async (code: string) => {
    try {
      const res = await fetch('http://localhost:8555/api/auth/mfa/verify', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify({ code })
      });
      if (!res.ok) {
         const err = await res.json();
         throw new Error(err.detail || "MFA Verify Failed");
      }
      setMfaSetupUri(null);
    } catch(e: any) {
      alert("MFA Error: " + e.message);
    }
  };

  const fetchServers = () => {
    if (!authToken || mfaSetupUri) return;
    fetchWithAuth('http://localhost:8555/api/virtual-servers/')
      .then(res => res.json())
      .then(data => { if(Array.isArray(data)) setServers(data) })
      .catch(err => console.error(err));
  };

  const fetchLogs = () => {
    if (!authToken || mfaSetupUri) return;
    const params = new URLSearchParams();
    if (filterServer && filterServer !== 'all') params.append('vs_id', filterServer);
    if (filterStatus && filterStatus !== 'all') params.append('status_class', filterStatus);
    if (searchTxt) params.append('search', searchTxt);
    params.append('page', currentPage.toString());
    params.append('limit', logsLimit.toString());
    
    fetchWithAuth('http://localhost:8555/api/logs?' + params.toString())
      .then(res => res.json())
      .then(data => { 
          if(data && Array.isArray(data.logs)) {
              setLogs(data.logs);
              setTotalLogs(data.total);
          }
      })
      .catch(err => console.error(err));
  };

  useEffect(() => {
    fetchServers();
    const interval = setInterval(fetchServers, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [filterServer, filterStatus, searchTxt, currentPage, logsLimit]);

  const handleFilterChange = (setter: any) => (e: any) => {
      setter(e.target.value);
      setCurrentPage(1);
  };

  const fetchData = () => { fetchServers(); fetchLogs(); };

  const handleDeploySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await fetchWithAuth('http://localhost:8555/api/virtual-servers/', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newServer),
      });
      fetchData();
      setIsDeployModalOpen(false);
    } catch (e) {
      console.error(e);
    }
  };

  const handleDelete = async (id: string) => {
    await fetchWithAuth('http://localhost:8555/api/virtual-servers/' + id, { method: 'DELETE' });
    fetchData();
  };

  const updateServerSettings = async (server: any, updates: any) => {
    const updated = { ...server, ...updates };

    // Format profiles correctly for the local UI state if it's an array of strings
    if (updates.profiles && updates.profiles.length > 0 && typeof updates.profiles[0] === 'string') {
        updated.profiles = updates.profiles.map((p: string) => ({ id: 'temp', profile_name: p }));
    } else if (updates.profiles && updates.profiles.length === 0) {
        updated.profiles = [];
    }

    // Format profiles correctly for the API payload (List[str])
    const currentProfiles = updated.profiles || [];
    const profileStrings = currentProfiles.map((p: any) => typeof p === 'string' ? p : p.profile_name);

    const apiPayload = { ...updated, profiles: profileStrings };

    try {
      const res = await fetchWithAuth('http://localhost:8555/api/virtual-servers/' + server.id, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(apiPayload),
      });
      
      if (!res.ok) {
          console.error("API Update Failed", await res.text());
      }
      
      fetchData();
      if (activeServer && activeServer.id === server.id) {
         setActiveServer(updated);
      }
    } catch(e) {
      console.error(e);
    }
  };

  const excludePath = async (log: any) => {
    if (!log.server) return;
    const srv = servers.find(s => s.name === log.server);
    if(!srv) return;
    
    try {
      await fetchWithAuth(`http://localhost:8555/api/exclusions?vs_id=${srv.id}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ path_pattern: log.path, rule_type: 'ALL' }),
      });
      fetchData();
    } catch(e) {
      console.error(e);
    }
  };

  const deleteExclusion = async (excId: string) => {
    try {
      await fetchWithAuth(`http://localhost:8555/api/exclusions/${excId}`, { method: 'DELETE' });
      fetchData();
      if (activeServer) {
        setActiveServer({
           ...activeServer,
           exclusions: activeServer.exclusions.filter((e: any) => e.id !== excId)
        });
      }
    } catch(e) {
      console.error(e);
    }
  };

  const addHeader = async () => {
    if (!activeServer || !newHeader.header_key) return;
    try {
      await fetchWithAuth(`http://localhost:8555/api/headers?vs_id=${activeServer.id}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newHeader),
      });
      setNewHeader({ direction: 'Response', header_key: '', header_value: '' });
      fetchData();
      const res = await fetchWithAuth(`http://localhost:8555/api/virtual-servers/${activeServer.id}`);
      setActiveServer(await res.json());
    } catch(e) { console.error(e); }
  };

  const deleteHeader = async (hdrId: string) => {
    try {
      await fetchWithAuth(`http://localhost:8555/api/headers/${hdrId}`, { method: 'DELETE' });
      fetchData();
      if (activeServer) {
        setActiveServer({
           ...activeServer,
           headers: activeServer.headers.filter((h: any) => h.id !== hdrId)
        });
      }
    } catch(e) { console.error(e); }
  };

  if (!authToken) {
      return <LoginView onLogin={handleLogin} mfaRequired={needsMfaCode} errorMsg={loginError} />;
  }

  if (mfaSetupUri) {
      return <MFASetupView setupUri={mfaSetupUri} onVerify={handleMfaVerify} />;
  }

  return (
    <div className="flex flex-col items-center min-h-screen p-10 bg-gradient-to-br from-slate-900 to-indigo-950">
      <div className="flex items-center mb-6 w-full max-w-5xl justify-between border-b border-indigo-500/30 pb-4">
        <div className="flex items-center space-x-4">
          <img src="/cybershield_logo.png" alt="CyberShield Logo" className="h-14 w-14 object-contain shadow-indigo-500/50 drop-shadow-[0_0_15px_rgba(79,70,229,0.5)] rounded-2xl" />
          <h1 className="text-2xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-300 hidden md:block">
            CyberShield
          </h1>
        </div>
        <div className="flex space-x-3 overflow-x-auto whitespace-nowrap custom-scrollbar pb-1">
          <button onClick={() => setActiveTab('servers')} className={`flex items-center flex-shrink-0 px-4 py-2 rounded-lg font-semibold transition ${activeTab === 'servers' ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'}`}>
            <Server className="w-5 h-5 flex-shrink-0 mr-2" /> Virtual Servers
          </button>
          <button onClick={() => setActiveTab('logs')} className={`flex items-center flex-shrink-0 px-4 py-2 rounded-lg font-semibold transition ${activeTab === 'logs' ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'}`}>
            <Terminal className="w-5 h-5 flex-shrink-0 mr-2" /> Traffic Logs
          </button>
          {currentUser?.role === 'admin' && (
            <button onClick={() => setActiveTab('users')} className={`flex items-center flex-shrink-0 px-4 py-2 rounded-lg font-semibold transition ${activeTab === 'users' ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'}`}>
              <Users className="w-5 h-5 flex-shrink-0 mr-2" /> Users
            </button>
          )}
          <button onClick={handleLogout} className="flex items-center flex-shrink-0 px-4 py-2 rounded-lg font-semibold transition bg-red-900/30 text-red-500 hover:bg-red-800 hover:text-white border border-red-500/30">
            <LogOut className="w-5 h-5 flex-shrink-0 mr-2" /> Logout
          </button>
        </div>
      </div>

      <div className="w-full max-w-5xl">
        {activeTab === 'servers' && (
          <div>
            <div className="flex justify-end mb-4">
              {currentUser?.role === 'admin' && (
                  <button onClick={() => setIsDeployModalOpen(true)} className="flex items-center bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-full transition-all shadow-[0_0_15px_rgba(79,70,229,0.5)]">
                    <PlusCircle className="w-5 h-5 mr-2" /> Add Virtual Server
                  </button>
              )}
            </div>
            <div className="grid grid-flow-row gap-6">
              {servers.length === 0 ? (
                <div className="text-slate-400 italic text-center p-10 bg-slate-800/40 rounded-xl border border-slate-700/50 backdrop-blur-md">No Virtual Servers configured yet.</div>
              ) : (
                servers.map(vs => (
                  <div key={vs.id} className="bg-[#1e2333]/80 p-6 rounded-2xl shadow-lg border border-slate-700/60 backdrop-blur-xl flex justify-between items-center transition-colors">
                    <div className="flex items-center">
                      <div className={`p-4 rounded-xl mr-5 ${vs.active ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                        <Server className="w-8 h-8 " />
                      </div>
                      <div>
                        <h2 className="text-2xl font-semibold text-white tracking-wide">{vs.name}</h2>
                        <div className="flex space-x-4 mt-2 text-sm text-slate-400">
                          <span className="flex items-center"><Activity className="w-4 h-4 mr-1 text-blue-400"/> Port {vs.ingress_port}</span>
                          <span>→ {vs.backend_target}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col items-end">
                      <div className="flex space-x-2">
                        {currentUser?.role === 'admin' && (
                            <button onClick={() => { setActiveServer(vs); setIsSettingsModalOpen(true); }} className="flex items-center bg-slate-700 hover:bg-slate-600 text-white px-3 py-1.5 rounded-lg text-sm font-medium transition">
                              <Shield className="w-4 h-4 mr-1"/> WAF Settings
                            </button>
                        )}
                      </div>
                      <div className="mt-3 flex items-center space-x-2">
                        <span className="text-xs text-slate-500 font-mono flex items-center border border-slate-700 px-2 py-0.5 rounded">
                           Exceptions: {vs.exclusions?.length || 0}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${vs.waf_mode === 'Blocking' ? 'bg-red-900/50 text-red-300' : vs.waf_mode === 'Logging' ? 'bg-yellow-900/50 text-yellow-300' : 'bg-slate-700/50 text-slate-300'}`}>
                          {vs.waf_mode}
                        </span>
                        {currentUser?.role === 'admin' && (
                            <button onClick={() => handleDelete(vs.id)} className="text-slate-500 hover:text-red-400 p-1 rounded">
                              <Trash2 className="w-4 h-4" />
                            </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="bg-[#0b0f19] rounded-xl border border-slate-700/50 p-4 shadow-2xl overflow-hidden font-mono text-sm">
             <div className="flex justify-between items-center mb-4 px-2">
                 <div className="text-white font-bold flex items-center">
                    <AlertOctagon className="w-4 h-4 mr-2" /> Live Traffic Stream
                 </div>
                 <div className="flex items-center space-x-3">
                    <input type="text" placeholder="Search path, user-agent, payload..." value={searchTxt} onChange={handleFilterChange(setSearchTxt)} className="bg-slate-800 text-slate-300 rounded p-1.5 border border-slate-700 outline-none focus:border-indigo-500 text-xs w-56" />
                    <select value={filterStatus} onChange={handleFilterChange(setFilterStatus)} className="bg-slate-800 text-slate-300 rounded p-1.5 border border-slate-700 outline-none focus:border-indigo-500 text-xs">
                       <option value="all">All Statuses</option>
                       <option value="2xx">Success (2xx)</option>
                       <option value="4xx">Client Errors (4xx)</option>
                       <option value="5xx">Server Errors (5xx)</option>
                       <option value="blocked">Blocked (403)</option>
                    </select>
                    <select value={filterServer} onChange={handleFilterChange(setFilterServer)} className="bg-slate-800 text-slate-300 rounded p-1.5 border border-slate-700 outline-none focus:border-indigo-500 text-xs max-w-[150px] truncate">
                       <option value="all">All Servers</option>
                       {servers.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                    </select>
                 </div>
             </div>
             <div className="flex text-slate-400 border-b border-slate-700 pb-2 mb-2 font-bold px-2">
               <div className="w-48">TIMESTAMP</div>
               <div className="w-24">METHOD</div>
               <div className="w-48">SERVER</div>
               <div className="flex-1">PATH</div>
               <div className="w-24">STATUS</div>
             </div>
             <div className="flex flex-col space-y-1">
               {logs.length === 0 && <div className="text-slate-500 italic p-4 text-center">No logs available at this time.</div>}
               {logs.map((log, idx) => {
                  const logId = `${log.time}-${idx}`;
                  const isBlocked = log.status == 403 || log.status == 406;
                  return (
                   <React.Fragment key={logId}>
                     <div onClick={() => setExpandedLogId(expandedLogId === logId ? null : logId)} 
                          className={`flex items-center px-2 py-1.5 rounded cursor-pointer transition ${isBlocked ? 'bg-red-900/20 hover:bg-red-900/40 text-red-300' : 'hover:bg-slate-800 text-green-400'} border border-transparent hover:border-slate-700`}>
                        <div className="w-48 text-slate-500">{new Date(log.time).toLocaleTimeString()}</div>
                        <div className="w-24 font-bold">{log.method}</div>
                        <div className="w-48 text-blue-400">{log.server}</div>
                        <div className="flex-1 truncate pr-4 text-slate-300">{log.path}</div>
                        <div className="w-32 flex items-center space-x-2">
                           <span className={isBlocked ? "font-bold" : "text-slate-400"}>{log.status}</span>
                           {isBlocked && (
                               <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${(log.block_reason && log.block_reason.includes('wasm')) || isBlocked ? 'bg-red-600 text-white' : 'bg-orange-500 text-white'}`}>
                                   {(log.block_reason && log.block_reason.includes('wasm')) || isBlocked ? 'WAF' : 'APP'}
                               </span>
                           )}
                           {expandedLogId === logId ? <ChevronUp className="w-4 h-4 text-slate-600"/> : <ChevronDown className="w-4 h-4 text-slate-600"/>}
                        </div>
                     </div>
                     {expandedLogId === logId && (
                       <div className="bg-slate-900 p-4 mx-2 rounded-b border-x border-b border-slate-700 mb-2 shadow-inner">
                         <div className="grid grid-cols-2 gap-4 text-slate-400 mb-4 border-b border-slate-800 pb-4">
                           <div><span className="font-bold text-slate-300">Target Server:</span> {log.server}</div>
                           <div><span className="font-bold text-slate-300">Client IP:</span> {log.client_ip}</div>
                           <div><span className="font-bold text-slate-300">Duration:</span> {log.duration}ms</div>
                           <div><span className="font-bold text-slate-300">User Agent:</span> {log.user_agent}</div>
                           {log.block_reason && (
                             <div className="col-span-2 mt-2 px-3 py-2 bg-slate-800/50 rounded-lg border border-slate-700/50">
                               <span className="font-bold text-slate-300">Intercept Reason: </span> 
                               <span className="font-mono text-xs text-red-400">{log.block_reason}</span>
                             </div>
                           )}
                         </div>
                         {(log.req_body || log.resp_body) && (
                           <div className="grid grid-cols-2 gap-4 mb-4">
                             <div>
                               <div className="text-xs font-bold text-slate-500 mb-1">REQUEST PAYLOAD</div>
                               <pre className="bg-slate-950 p-3 rounded-lg text-xs font-mono text-green-400 overflow-x-auto whitespace-pre-wrap max-h-48 shadow-inner border border-slate-800/60">{log.req_body || 'No body captured'}</pre>
                             </div>
                             <div>
                               <div className="text-xs font-bold text-slate-500 mb-1">RESPONSE PAYLOAD</div>
                               <pre className="bg-slate-950 p-3 rounded-lg text-xs font-mono text-blue-400 overflow-x-auto whitespace-pre-wrap max-h-48 shadow-inner border border-slate-800/60">{log.resp_body || 'No body captured'}</pre>
                             </div>
                           </div>
                         )}
                         {isBlocked && currentUser?.role === 'admin' && (
                           <div className="flex justify-end pt-2 border-t border-slate-800">
                             <button onClick={() => excludePath(log)} className="flex items-center bg-red-900/50 hover:bg-red-800 text-red-200 px-3 py-1 rounded text-xs transition">
                                <AlertOctagon className="w-3 h-3 mr-1" /> Add Exclusion for path
                             </button>
                           </div>
                         )}
                       </div>
                     )}
                   </React.Fragment>
                  );
               })}
             </div>
             <div className="flex justify-between items-center mt-4 bg-slate-800/80 p-2 rounded-lg border border-slate-700/60 shadow-inner">
               <div className="text-slate-400 text-xs">
                 Showing {logs.length > 0 ? (currentPage - 1) * logsLimit + 1 : 0} - {Math.min(currentPage * logsLimit, totalLogs)} of <span className="font-bold text-slate-300">{totalLogs}</span> matching logs
               </div>
               <div className="flex items-center space-x-4">
                 <select value={logsLimit} onChange={e => { setLogsLimit(parseInt(e.target.value)); setCurrentPage(1); }} className="bg-slate-900 border border-slate-700 text-slate-300 rounded px-2 py-1 outline-none focus:border-indigo-500 text-xs cursor-pointer hover:border-slate-500">
                    <option value="100">100 / page</option>
                    <option value="200">200 / page</option>
                    <option value="500">500 / page</option>
                 </select>
                 <div className="flex items-center space-x-1.5">
                   <button disabled={currentPage <= 1} onClick={() => setCurrentPage(p => p - 1)} className="px-3 py-1 bg-slate-700 hover:bg-indigo-600 text-white rounded text-xs transition disabled:opacity-40 disabled:hover:bg-slate-700 disabled:cursor-not-allowed border border-slate-600 font-bold">Prev</button>
                   <span className="text-slate-300 text-xs px-2 font-mono">{currentPage} / {Math.ceil(totalLogs / logsLimit) || 1}</span>
                   <button disabled={currentPage * logsLimit >= totalLogs} onClick={() => setCurrentPage(p => p + 1)} className="px-3 py-1 bg-slate-700 hover:bg-indigo-600 text-white rounded text-xs transition disabled:opacity-40 disabled:hover:bg-slate-700 disabled:cursor-not-allowed border border-slate-600 font-bold">Next</button>
                 </div>
               </div>
             </div>
          </div>
        )}

        {activeTab === 'users' && currentUser?.role === 'admin' && (
            <UsersTab authToken={authToken} />
        )}
      </div>

      {isDeployModalOpen && (
        <div className="fixed inset-0 backdrop-blur-md bg-black/60 flex justify-center items-center z-50">
          <div className="bg-slate-900/90 border border-slate-700 p-8 rounded-2xl shadow-2xl w-full max-w-md mx-auto relative">
            <button onClick={() => setIsDeployModalOpen(false)} className="absolute top-4 right-4 text-slate-400 hover:text-white transition">
              <X className="w-6 h-6" />
            </button>
            <h2 className="text-2xl font-semibold mb-6 text-white flex items-center">
              <PlusCircle className="mr-2"/> Add Virtual Server
            </h2>
            <form onSubmit={handleDeploySubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
                <input type="text" name="name" value={newServer.name} onChange={(e) => setNewServer({...newServer, name: e.target.value})} required className="w-full bg-slate-800 text-white p-3 rounded-lg outline-none focus:ring-2 ring-indigo-500 border border-slate-700" placeholder="e.g. Intranet Site" />
              </div>
              <div className="flex space-x-4">
                <div className="w-1/2">
                  <label className="block text-sm font-medium text-slate-300 mb-1">Ingress Port</label>
                  <input type="number" name="ingress_port" value={newServer.ingress_port} onChange={(e) => setNewServer({...newServer, ingress_port: parseInt(e.target.value)})} required className="w-full bg-slate-800 text-white p-3 rounded-lg outline-none focus:ring-2 ring-indigo-500 border border-slate-700" placeholder="e.g. 8002" />
                </div>
                <div className="w-1/2">
                  <label className="block text-sm font-medium text-slate-300 mb-1">Retention (Days)</label>
                  <input type="number" min="1" max="365" name="retention" value={newServer.log_retention_days} onChange={(e) => setNewServer({...newServer, log_retention_days: parseInt(e.target.value)})} required className="w-full bg-slate-800 text-white p-3 rounded-lg outline-none focus:ring-2 ring-indigo-500 border border-slate-700" />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Backend Target</label>
                <input type="text" name="backend_target" value={newServer.backend_target} onChange={(e) => setNewServer({...newServer, backend_target: e.target.value})} required className="w-full bg-slate-800 text-white p-3 rounded-lg outline-none focus:ring-2 ring-indigo-500 border border-slate-700" placeholder="e.g. 10.0.1.50:80" />
              </div>
              <button type="submit" className="w-full bg-indigo-600 font-semibold text-white p-3 mt-4 rounded-lg hover:bg-indigo-500 transition shadow-[0_0_15px_rgba(79,70,229,0.4)]">
                Create & Deploy
              </button>
            </form>
          </div>
        </div>
      )}
      
      {/* Settings Modal */}
      {isSettingsModalOpen && activeServer && (
        <div className="fixed inset-0 backdrop-blur-md bg-black/60 flex justify-center items-center z-50">
          <div className="bg-slate-900 border border-slate-700 p-8 rounded-2xl shadow-2xl w-full max-w-4xl mx-auto relative h-[85vh] flex flex-col">
            <button onClick={() => setIsSettingsModalOpen(false)} className="absolute top-4 right-4 text-slate-400 hover:text-white transition">
              <X className="w-6 h-6" />
            </button>
            <div className="flex-shrink-0">
                <h2 className="text-3xl font-semibold mb-2 text-white flex items-center">
                  <Shield className="w-8 h-8 mr-3 text-indigo-400"/> Threat Engine Tuning
                </h2>
                <p className="text-slate-400 mb-6 font-medium">Fine-tune the security posture and technology profile for <span className="font-bold text-white bg-slate-800 px-2 py-1 rounded">{activeServer.name}</span></p>
                
                 <div className="flex space-x-2 border-b border-slate-700 mb-6 font-mono text-sm">
                   <button onClick={() => setActiveSettingsTab('rules')} className={`px-4 py-2 transition ${activeSettingsTab === 'rules' ? 'text-indigo-400 border-b-2 border-indigo-400' : 'text-slate-400 hover:text-white'}`}>
                      Core Rules
                   </button>
                   <button onClick={() => setActiveSettingsTab('apps')} className={`px-4 py-2 transition ${activeSettingsTab === 'apps' ? 'text-indigo-400 border-b-2 border-indigo-400' : 'text-slate-400 hover:text-white'}`}>
                      Apps Tuning
                   </button>
                   <button onClick={() => setActiveSettingsTab('exclusions')} className={`px-4 py-2 transition ${activeSettingsTab === 'exclusions' ? 'text-indigo-400 border-b-2 border-indigo-400' : 'text-slate-400 hover:text-white'}`}>
                      Exclusions
                   </button>
                   <button onClick={() => setActiveSettingsTab('headers')} className={`px-4 py-2 transition ${activeSettingsTab === 'headers' ? 'text-indigo-400 border-b-2 border-indigo-400' : 'text-slate-400 hover:text-white'}`}>
                      Custom Headers
                   </button>
                   <button onClick={() => setActiveSettingsTab('ddos')} className={`px-4 py-2 transition ${activeSettingsTab === 'ddos' ? 'text-indigo-400 border-b-2 border-indigo-400' : 'text-slate-400 hover:text-white'}`}>
                      DDoS Protection
                   </button>
                </div>
            </div>
            
            <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-4">
              {activeSettingsTab === 'rules' && (
                 <div className="grid grid-cols-2 gap-4">
                    {ruleCategories.map(cat => {
                        const Icon = cat.icon;
                        const isEnabled = activeServer.profiles?.some((p: any) => p.profile_name === cat.id);
                        return (
                           <div key={cat.id} className="bg-slate-800 p-4 rounded-xl flex justify-between items-center border border-slate-700/60 hover:border-slate-600 transition">
                             <div className="flex items-center space-x-3 w-3/4">
                               <div className={`p-2 rounded-lg ${isEnabled ? 'bg-indigo-500/20 text-indigo-400' : 'bg-slate-700 text-slate-500'}`}>
                                 <Icon className="w-5 h-5"/>
                               </div>
                               <div>
                                 <h3 className="text-slate-200 font-bold tracking-wide">{cat.label}</h3>
                                 <p className="text-slate-400 text-xs mt-1">{cat.desc}</p>
                               </div>
                             </div>
                             <button onClick={() => {
                                 const current = activeServer.profiles?.map((p:any) => p.profile_name) || [];
                                 const next = isEnabled ? current.filter((c:any) => c !== cat.id) : [...current, cat.id];
                                 updateServerSettings(activeServer, { profiles: next });
                             }} className={`w-12 h-6 rounded-full transition-colors relative flex-shrink-0 ${isEnabled ? 'bg-indigo-500' : 'bg-slate-600'}`}>
                                <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-all shadow ${isEnabled ? 'left-7' : 'left-1'}`}></div>
                             </button>
                           </div>
                        );
                    })}
                 </div>
              )}

              {activeSettingsTab === 'apps' && (
                 <div className="grid grid-cols-2 gap-4">
                    {appCategories.map(cat => {
                        const Icon = cat.icon;
                        const isEnabled = activeServer.profiles?.some((p: any) => p.profile_name === cat.id);
                        // In the future we can extract the auto-detected badge logic here
                        return (
                           <div key={cat.id} className={`bg-slate-800 p-4 rounded-xl flex justify-between items-center border transition ${isEnabled ? 'border-blue-500/50 bg-blue-900/10' : 'border-slate-700/60'}`}>
                             <div className="flex items-center space-x-3 w-3/4">
                               <div className={`p-2 rounded-lg ${isEnabled ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-700 text-slate-500'}`}>
                                 <Icon className="w-5 h-5"/>
                               </div>
                               <div>
                                 <div className="flex items-center">
                                    <h3 className="text-slate-200 font-bold tracking-wide mr-2">{cat.label}</h3>
                                    {isEnabled && <span className="bg-blue-600/30 text-blue-400 text-[10px] px-1.5 py-0.5 rounded uppercase font-bold tracking-wider">Active</span>}
                                 </div>
                                 <p className="text-slate-400 text-xs mt-1">{cat.desc}</p>
                               </div>
                             </div>
                             <button onClick={() => {
                                 const current = activeServer.profiles?.map((p:any) => p.profile_name) || [];
                                 const next = isEnabled ? current.filter((c:any) => c !== cat.id) : [...current, cat.id];
                                 updateServerSettings(activeServer, { profiles: next });
                             }} className={`w-12 h-6 rounded-full transition-colors relative flex-shrink-0 ${isEnabled ? 'bg-blue-500' : 'bg-slate-600'}`}>
                                <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-all shadow ${isEnabled ? 'left-7' : 'left-1'}`}></div>
                             </button>
                           </div>
                        );
                    })}
                 </div>
              )}

              {activeSettingsTab === 'exclusions' && (
                 <div className="space-y-4">
                    {(!activeServer.exclusions || activeServer.exclusions.length === 0) ? (
                        <div className="text-slate-500 italic p-6 text-center bg-slate-800/50 rounded-xl border border-slate-700/50">No path exclusions configured for this server.</div>
                    ) : (
                        activeServer.exclusions.map((exc: any) => (
                           <div key={exc.id} className="bg-slate-800 p-4 rounded-xl flex justify-between items-center border border-slate-700/60 transition hover:border-slate-600">
                             <div className="flex items-center space-x-3 w-3/4">
                               <div className="p-2 rounded-lg bg-red-900/40 text-red-500">
                                 <AlertOctagon className="w-5 h-5"/>
                               </div>
                               <div>
                                 <h3 className="text-slate-200 font-bold tracking-wide font-mono text-sm">{exc.path_pattern}</h3>
                                 <p className="text-slate-400 text-xs mt-1">Rule bypass: {exc.rule_type}</p>
                               </div>
                             </div>
                             <button onClick={() => deleteExclusion(exc.id)} className="p-2 hover:bg-red-900/50 text-slate-500 hover:text-red-400 rounded-lg transition" title="Remove Exclusion">
                               <Trash2 className="w-5 h-5" />
                             </button>
                           </div>
                        ))
                    )}
                 </div>
              )}

              {activeSettingsTab === 'headers' && (
                 <div className="space-y-4">
                    <div className="flex space-x-2 p-4 bg-slate-800 rounded-xl border border-slate-700/60 items-end">
                       <div className="w-1/4">
                          <label className="block text-xs uppercase tracking-wide text-slate-400 mb-1">Direction</label>
                          <select value={newHeader.direction} onChange={e => setNewHeader({...newHeader, direction: e.target.value})} className="w-full bg-slate-900 border border-slate-700 text-white rounded p-2 text-sm outline-none">
                             <option value="Response">Response (To Client)</option>
                             <option value="Request">Request (To Upstream)</option>
                          </select>
                       </div>
                       <div className="w-1/3">
                          <label className="block text-xs uppercase tracking-wide text-slate-400 mb-1">Header Key</label>
                          <input type="text" placeholder="e.g. X-Frame-Options" value={newHeader.header_key} onChange={e => setNewHeader({...newHeader, header_key: e.target.value})} className="w-full bg-slate-900 border border-slate-700 text-white rounded p-2 text-sm outline-none" />
                       </div>
                       <div className="flex-1">
                          <label className="block text-xs uppercase tracking-wide text-slate-400 mb-1">Header Value</label>
                          <input type="text" placeholder="e.g. DENY" value={newHeader.header_value} onChange={e => setNewHeader({...newHeader, header_value: e.target.value})} className="w-full bg-slate-900 border border-slate-700 text-white rounded p-2 text-sm outline-none" />
                       </div>
                       <button onClick={addHeader} disabled={!newHeader.header_key} className="bg-indigo-600 hover:bg-indigo-500 text-white p-2 rounded disabled:opacity-50 h-[38px] flex justify-center items-center">
                          <PlusCircle className="w-5 h-5" />
                       </button>
                    </div>
                    
                    {(!activeServer.headers || activeServer.headers.length === 0) ? (
                        <div className="text-slate-500 italic p-6 text-center bg-slate-800/50 rounded-xl border border-slate-700/50">No custom headers configured for this server.</div>
                    ) : (
                        activeServer.headers.map((hdr: any) => (
                           <div key={hdr.id} className="bg-slate-800 p-4 rounded-xl flex justify-between items-center border border-slate-700/60">
                             <div className="flex items-center space-x-3 flex-1">
                               <div className={`px-2 py-1 rounded font-bold text-[10px] uppercase ${hdr.direction === 'Response' ? 'bg-indigo-900/40 text-indigo-400 border border-indigo-500/30' : 'bg-pink-900/40 text-pink-400 border border-pink-500/30'}`}>
                                 {hdr.direction}
                               </div>
                               <div>
                                 <h3 className="text-slate-200 font-bold font-mono text-sm">{hdr.header_key}: <span className="text-slate-400">{hdr.header_value}</span></h3>
                               </div>
                             </div>
                             <button onClick={() => deleteHeader(hdr.id)} className="p-2 hover:bg-red-900/50 text-slate-500 hover:text-red-400 rounded-lg transition" title="Delete Header">
                               <Trash2 className="w-5 h-5" />
                             </button>
                           </div>
                        ))
                    )}
                 </div>
              )}

              {activeSettingsTab === 'ddos' && (
                 <div className="space-y-6 bg-slate-800 p-6 rounded-xl border border-slate-700/60">
                    <div className="flex justify-between items-center mb-4">
                       <div>
                          <h3 className="text-xl font-bold text-white flex items-center">
                             <Shield className="w-6 h-6 mr-2 text-indigo-400" /> Native Rate Limiting
                          </h3>
                          <p className="text-slate-400 text-sm mt-1">Blocks excessive traffic from a single IP address using Envoy's native HTTP local rate limit filter.</p>
                       </div>
                       <button onClick={() => {
                           const isEnabled = activeServer.rate_limit_enabled || false;
                           updateServerSettings(activeServer, { rate_limit_enabled: !isEnabled });
                       }} className={`w-14 h-7 rounded-full transition-colors relative flex-shrink-0 ${activeServer.rate_limit_enabled ? 'bg-indigo-500' : 'bg-slate-600'}`}>
                          <div className={`absolute top-1 w-5 h-5 bg-white rounded-full transition-all shadow-md ${activeServer.rate_limit_enabled ? 'left-8' : 'left-1'}`}></div>
                       </button>
                    </div>

                    <div className={`transition-opacity ${activeServer.rate_limit_enabled ? 'opacity-100' : 'opacity-50 pointer-events-none'}`}>
                        <label className="block text-sm font-medium text-slate-300 mb-2">Max Requests Per Minute (RPM)</label>
                        <div className="flex items-center space-x-4">
                            <input type="number" min="1" max="10000" disabled={!activeServer.rate_limit_enabled} value={activeServer.rate_limit_rpm !== undefined ? activeServer.rate_limit_rpm : 100}
                               onChange={(e) => updateServerSettings(activeServer, { rate_limit_rpm: parseInt(e.target.value) })}
                               className="w-1/3 bg-slate-900 border border-slate-700 text-white p-3 rounded-lg outline-none focus:ring-2 focus:ring-indigo-500 transition" />
                            <span className="text-slate-400 text-sm">Requests per 60 seconds per individual remote IP address.</span>
                        </div>
                    </div>
                 </div>
              )}
            </div>
              
            <div className="flex-shrink-0 mt-6 pt-6 border-t border-slate-700 flex space-x-6 items-center">
               <div className="flex-1">
                 <label className="block text-sm font-semibold text-slate-300 mb-2 uppercase tracking-wide">Operation Mode</label>
                 <select value={activeServer.waf_mode} onChange={(e) => updateServerSettings(activeServer, { waf_mode: e.target.value })} className="w-full bg-slate-800 text-white p-3 rounded-xl border border-slate-700 outline-none focus:ring-2 focus:ring-indigo-500 transition shadow-inner">
                    <option value="Blocking">🛡️ Blocking (Active Prevention & Anomaly Threshold)</option>
                    <option value="Logging">👁️ Logging (Monitor Only)</option>
                    <option value="Disabled">❌ Disabled</option>
                 </select>
               </div>
               <div className="flex-none">
                   <button onClick={() => setIsSettingsModalOpen(false)} className="px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl shadow-lg mt-6 shadow-indigo-500/30 transition-all">
                       Done Tuning
                   </button>
               </div>
            </div>
            
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
