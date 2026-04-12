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
    <div className={`glass-card p-6 overflow-hidden group animate-reveal opacity-0`} style={{ animationDelay: delay }}>
      <div className={`absolute -right-6 -top-6 w-24 h-24 rounded-full blur-3xl opacity-10 group-hover:opacity-30 transition-opacity duration-500 ${colorClass.replace('text', 'bg')}`}></div>
      <div className="flex items-center justify-between mb-4 relative z-10">
        <h3 className="text-slate-500 font-bold tracking-[0.2em] text-[10px] uppercase">{title}</h3>
        <div className={`p-2.5 rounded-xl bg-white/5 border border-white/10 ${colorClass} shadow-glass`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="relative z-10 flex items-end space-x-3">
        <span className={`text-4xl font-black text-white tracking-tighter ${colorClass.includes('cyan') ? 'text-glow-cyan' : ''}`}>
          {stats ? value : '---'}
        </span>
        {stats && <div className="flex items-center mb-1.5">
          <div className={`w-1.5 h-1.5 rounded-full ${colorClass.replace('text', 'bg')} animate-pulse mr-1.5 shadow-[0_0_8px_currentColor]`} />
          <span className={`text-[10px] font-black uppercase tracking-widest opacity-70 ${colorClass}`}>Live</span>
        </div>}
      </div>
    </div>
  );

  return (
    <div className="w-full relative z-10 min-h-[70vh]">
      <div className="mb-12 text-center">
        <h2 className="text-5xl font-black text-white tracking-tighter mb-2">
          System <span className="text-transparent bg-clip-text bg-gradient-to-r from-lumina-cyan to-lumina-indigo">Telemetry</span>
        </h2>
        <div className="flex items-center justify-center space-x-4">
          <div className="h-[1px] w-12 bg-gradient-to-r from-transparent to-white/20" />
          <p className="text-slate-500 font-bold text-[11px] tracking-[0.3em] uppercase">Real-Time Infrastructure Oversight</p>
          <div className="h-[1px] w-12 bg-gradient-to-l from-transparent to-white/20" />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12 max-w-6xl mx-auto">
        <MetricCard title="Total Traffic (24H)" value={stats?.total_requests_24h.toLocaleString()} icon={Activity} colorClass="text-lumina-cyan" delay="0ms" />
        <MetricCard title="Threats Blocked (24H)" value={stats?.total_blocked_24h.toLocaleString()} icon={ShieldAlert} colorClass="text-rose-500" delay="100ms" />
        <MetricCard title="Quarantined IPs" value={stats?.active_blacklisted_ips.toLocaleString()} icon={Zap} colorClass="text-orange-400" delay="200ms" />
        <MetricCard title="Nodes Online" value={stats?.active_virtual_servers} icon={Server} colorClass="text-green-400" delay="300ms" />
      </div>

      {/* Animated Topology Graph */}
      <div className="max-w-4xl mx-auto glass-panel rounded-[2rem] p-10 overflow-hidden relative">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-lumina-cyan/30 to-transparent" />
        <h3 className="text-white font-bold tracking-[0.3em] text-[11px] mb-12 flex items-center justify-center uppercase">
          <Cpu className="w-4 h-4 mr-3 text-lumina-cyan animate-pulse" /> Live Topology Stream
        </h3>
        
        <div className="flex items-center justify-between relative px-10">
           {/* Connecting Line */}
           <div className="absolute left-16 right-16 top-1/2 h-[1px] bg-gradient-to-r from-white/5 via-white/20 to-white/5 -translate-y-1/2 z-0">
               {/* Animated Datagrams */}
               <div className="absolute top-[-3px] left-0 w-1.5 h-1.5 bg-lumina-cyan rounded-full shadow-[0_0_12px_#22d3ee] z-10 animate-[moveRight_2s_linear_infinite]" />
               <div className="absolute top-[-3px] left-[40%] w-1.5 h-1.5 bg-lumina-indigo rounded-full shadow-[0_0_12px_#6366f1] z-10 animate-[moveRight_2s_linear_infinite]" style={{animationDelay: '0.7s'}} />
               <div className="absolute top-[-3px] left-[75%] w-1.5 h-1.5 bg-green-400 rounded-full shadow-[0_0_12px_#4ade80] z-10 animate-[moveRight_2.5s_linear_infinite]" style={{animationDelay: '1.4s'}} />
           </div>

           {/* Edge Node (Internet) */}
           <div className="relative z-10 flex flex-col items-center group">
              <div className="w-20 h-20 rounded-2xl glass-card flex items-center justify-center group-hover:scale-110 transition-transform">
                 <Globe className="w-8 h-8 text-slate-500" />
              </div>
              <span className="text-[10px] text-slate-500 font-black mt-4 uppercase tracking-[0.2em]">Public Net</span>
           </div>

           {/* Envoy WAF Node */}
           <div className="relative z-10 flex flex-col items-center group">
              <div className="relative w-24 h-24 rounded-3xl bg-lumina-indigo/10 border border-lumina-indigo/30 flex items-center justify-center shadow-glow-indigo group-hover:shadow-[0_0_40px_rgba(99,102,241,0.6)] transition-all">
                 <div className="absolute inset-0 rounded-3xl border border-lumina-indigo/40 animate-pulse" />
                 <ShieldCheck className="w-10 h-10 text-lumina-indigo" />
              </div>
              <span className="text-[11px] text-lumina-indigo font-black mt-4 uppercase tracking-[0.2em]">LuminaWAF Gateway</span>
              <span className="text-[9px] text-green-400 px-3 py-0.5 rounded-full bg-green-500/10 font-black mt-2 border border-green-500/20 tracking-widest">SECURE</span>
           </div>

            {/* Target Backend */}
            <div className="relative z-10 flex flex-col items-center group">
               <div className={`w-20 h-20 rounded-2xl glass-card flex items-center justify-center group-hover:scale-110 transition-transform ${anyDown ? 'border-rose-500/50 shadow-rose-500/20' : ''}`}>
                  <Server className={`w-8 h-8 ${anyDown ? 'text-rose-400' : 'text-lumina-cyan'}`} />
               </div>
               <span className="text-[10px] text-slate-500 font-black mt-4 uppercase tracking-[0.2em]">Backends</span>
               <span className={`text-[9px] px-3 py-0.5 rounded-full font-black mt-2 border tracking-widest ${anyDown ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-green-500/10 text-green-400 border-green-500/20'}`}>
                  {anyDown ? 'PARTIAL' : 'HEALTHY'}
               </span>
            </div>

           {/* Storage */}
           <div className="relative z-10 flex flex-col items-center group">
              <div className="w-20 h-20 rounded-2xl glass-card flex items-center justify-center group-hover:scale-110 transition-transform">
                 <Database className="w-8 h-8 text-slate-500" />
              </div>
              <span className="text-[10px] text-slate-500 font-black mt-4 uppercase tracking-[0.2em]">Storage</span>
           </div>
        </div>

        <style dangerouslySetInnerHTML={{__html: `
          @keyframes moveRight {
            0% { left: 0%; opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { left: 100%; opacity: 0; }
          }
        `}} />
      </div>
    </div>
  );
};

export default DashboardTab;
