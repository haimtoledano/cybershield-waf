import React, { useState, useEffect } from 'react';
import { ShieldCheck, Activity, Database, Server, Cpu, Globe, ArrowRight, ShieldAlert, Zap } from 'lucide-react';

interface DashboardTabProps {
  authToken: string;
}

const DashboardTab: React.FC<DashboardTabProps> = ({ authToken }) => {
  const [stats, setStats] = useState<any>(null);
  const [servers, setServers] = useState<any[]>([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const headers = { 'Authorization': `Bearer ${authToken}` };
        const [statsRes, serversRes] = await Promise.all([
          fetch('http://localhost:8555/api/stats', { headers }),
          fetch('http://localhost:8555/api/virtual-servers/', { headers })
        ]);
        if (statsRes.ok) setStats(await statsRes.json());
        if (serversRes.ok) setServers(await serversRes.json());
      } catch (e) {
        console.error(e);
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [authToken]);

  const allHealthy = servers.every(s => s.is_online);
  const anyDown = servers.some(s => !s.is_online);

  const MetricCard = ({ title, value, icon: Icon, colorClass, delay }: any) => (
    <div className={`relative overflow-hidden bg-slate-900/40 backdrop-blur-xl border border-slate-700/50 p-6 rounded-2xl shadow-2xl transition-all duration-500 hover:scale-105 hover:border-${colorClass.split('-')[1]}/50 group animate-fade-in`} style={{ animationDelay: delay }}>
      <div className={`absolute -right-6 -top-6 w-24 h-24 rounded-full blur-2xl opacity-20 group-hover:opacity-40 transition-opacity duration-500 ${colorClass.replace('text', 'bg')}`}></div>
      <div className="flex items-center justify-between mb-4 relative z-10">
        <h3 className="text-slate-400 font-semibold tracking-wider text-sm uppercase">{title}</h3>
        <div className={`p-2 rounded-xl bg-slate-800/50 ${colorClass}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="relative z-10 flex items-end space-x-3">
        <span className="text-4xl font-black text-white tracking-tight">
          {stats ? value : '-'}
        </span>
        {stats && <span className={`text-xs mb-1 font-bold ${colorClass} animate-pulse`}>LIVE</span>}
      </div>
    </div>
  );

  return (
    <div className="w-full relative z-10 animate-fade-in min-h-[70vh]">
      {/* Background Starfield effect (CSS driven) */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden rounded-3xl z-[-1] opacity-40 mix-blend-screen">
          <div className="absolute top-1/4 left-1/4 w-1 h-1 bg-cyan-400 rounded-full shadow-[0_0_10px_#22d3ee] animate-ping" style={{animationDuration: '3s'}}></div>
          <div className="absolute top-1/2 right-1/3 w-1.5 h-1.5 bg-indigo-500 rounded-full shadow-[0_0_15px_#6366f1] animate-ping" style={{animationDuration: '4s', animationDelay: '1s'}}></div>
          <div className="absolute bottom-1/4 left-1/3 w-1 h-1 bg-purple-500 rounded-full shadow-[0_0_10px_#a855f7] animate-ping" style={{animationDuration: '2.5s', animationDelay: '2s'}}></div>
      </div>

      <div className="mb-10 text-center">
        <h2 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-500 to-indigo-400 animate-pulse drop-shadow-[0_0_20px_rgba(56,189,248,0.3)]">
          SYSTEM TELEMETRY
        </h2>
        <p className="text-slate-400 mt-2 font-mono text-sm tracking-widest">REAL-TIME INFRASTRUCTURE OVERSIGHT</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12 max-w-6xl mx-auto">
        <MetricCard title="Total Traffic (24H)" value={stats?.total_requests_24h.toLocaleString()} icon={Activity} colorClass="text-cyan-400" delay="0ms" />
        <MetricCard title="Threats Blocked (24H)" value={stats?.total_blocked_24h.toLocaleString()} icon={ShieldAlert} colorClass="text-red-500" delay="100ms" />
        <MetricCard title="Quarantined IPs" value={stats?.active_blacklisted_ips.toLocaleString()} icon={Zap} colorClass="text-orange-400" delay="200ms" />
        <MetricCard title="Active Virtual Servers" value={stats?.active_virtual_servers} icon={Server} colorClass="text-green-400" delay="300ms" />
      </div>

      {/* Animated Topology Graph */}
      <div className="max-w-4xl mx-auto bg-slate-900/60 backdrop-blur-md rounded-3xl border border-slate-700/50 p-8 shadow-[0_0_50px_rgba(0,0,0,0.5)] overflow-hidden relative">
        <h3 className="text-white font-bold tracking-widest mb-10 flex items-center justify-center">
          <Cpu className="w-5 h-5 mr-3 text-indigo-400" /> LIVE TOPOLOGY STREAM
        </h3>
        
        <div className="flex items-center justify-between relative px-10">
           {/* Connecting Line */}
           <div className="absolute left-16 right-16 top-1/2 h-0.5 bg-slate-700/50 -translate-y-1/2 z-0">
               {/* Animated Datagrams */}
               <div className="absolute top-[-3px] left-0 w-2 h-2 bg-cyan-400 rounded-full shadow-[0_0_10px_#22d3ee] z-10 animate-[moveRight_2s_linear_infinite]"></div>
               <div className="absolute top-[-3px] left-[30%] w-2 h-2 bg-indigo-500 rounded-full shadow-[0_0_10px_#6366f1] z-10 animate-[moveRight_2s_linear_infinite]" style={{animationDelay: '1s'}}></div>
               <div className="absolute top-[-3px] left-[60%] w-2 h-2 bg-green-400 rounded-full shadow-[0_0_10px_#4ade80] z-10 animate-[moveRight_2.5s_linear_infinite]" style={{animationDelay: '0.5s'}}></div>
           </div>

           {/* Edge Node (Internet) */}
           <div className="relative z-10 flex flex-col items-center group">
              <div className="w-16 h-16 rounded-2xl bg-slate-800 border border-slate-600 flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform">
                 <Globe className="w-8 h-8 text-slate-400" />
              </div>
              <span className="text-xs text-slate-400 font-bold mt-3 uppercase tracking-wider">Public Net</span>
           </div>

           {/* Envoy WAF Node */}
           <div className="relative z-10 flex flex-col items-center group">
              <div className="relative w-20 h-20 rounded-2xl bg-indigo-900/40 border border-indigo-500/50 flex items-center justify-center shadow-[0_0_30px_rgba(99,102,241,0.3)] group-hover:shadow-[0_0_40px_rgba(99,102,241,0.6)] transition-all">
                 <div className="absolute inset-0 rounded-2xl border-2 border-indigo-400 animate-pulse opacity-50"></div>
                 <ShieldCheck className="w-10 h-10 text-indigo-400" />
              </div>
              <span className="text-xs text-indigo-300 font-bold mt-3 uppercase tracking-wider">LuminaWAF Gateway</span>
              <span className="text-[10px] text-green-400 px-2 rounded-full bg-green-900/30 font-mono mt-1 border border-green-500/30">ONLINE</span>
           </div>

            {/* Target Backend */}
            <div className="relative z-10 flex flex-col items-center group">
               <div className={`w-16 h-16 rounded-2xl bg-slate-800 border flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform ${anyDown ? 'border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]' : 'border-slate-600'}`}>
                  <Server className={`w-8 h-8 ${anyDown ? 'text-red-400' : 'text-blue-400'}`} />
               </div>
               <span className="text-xs text-slate-400 font-bold mt-3 uppercase tracking-wider">Virtual Servers</span>
               <span className={`text-[10px] px-2 rounded-full font-mono mt-1 border ${anyDown ? 'bg-red-900/30 text-red-400 border-red-500/30' : 'bg-green-900/30 text-green-400 border-green-500/30'}`}>
                  {anyDown ? 'PARTIAL OUTAGE' : 'ALL HEALTHY'}
               </span>
            </div>

           {/* Database */}
           <div className="relative z-10 flex flex-col items-center group">
              <div className="w-16 h-16 rounded-2xl bg-slate-800 border border-slate-600 flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform">
                 <Database className="w-8 h-8 text-slate-400" />
              </div>
              <span className="text-xs text-slate-400 font-bold mt-3 uppercase tracking-wider">Storage</span>
           </div>
        </div>

        <style dangerouslySetInnerHTML={{__html: `
          @keyframes moveRight {
            0% { left: 0%; opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { left: 100%; opacity: 0; }
          }
          @keyframes fade-in {
            0% { opacity: 0; transform: translateY(10px); }
            100% { opacity: 1; transform: translateY(0); }
          }
          .animate-fade-in {
            animation: fade-in 0.6s ease-out forwards;
          }
        `}} />
      </div>
    </div>
  );
};

export default DashboardTab;
