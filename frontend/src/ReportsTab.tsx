import React, { useState, useEffect } from 'react';
import { 
  BarChart3, 
  PieChart as PieIcon, 
  Calendar, 
  ShieldAlert, 
  TrendingUp,
  Activity,
  BellRing
} from 'lucide-react';

interface ReportsTabProps {
  authToken: string;
}

const ReportsTab: React.FC<ReportsTabProps> = ({ authToken }) => {
  const [reportData, setReportData] = useState<any>(null);
  const [subscriptions, setSubscriptions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(1);

  const fetchReport = async () => {
    try {
      const res = await fetch(`http://localhost:8555/api/reports/preview?days=${days}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (res.ok) setReportData(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchSubscriptions = async () => {
    try {
      const res = await fetch(`http://localhost:8555/api/reports/subscriptions`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (res.ok) setSubscriptions(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchReport(), fetchSubscriptions()]).finally(() => setLoading(false));
  }, [days, authToken]);

  const toggleSubscription = async (frequency: string) => {
    const existing = subscriptions.find(s => s.frequency === frequency);
    try {
      if (existing) {
        await fetch(`http://localhost:8555/api/reports/subscriptions/${existing.id}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${authToken}` }
        });
      } else {
        await fetch(`http://localhost:8555/api/reports/subscriptions`, {
          method: 'POST',
          headers: { 
            'Authorization': `Bearer ${authToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ frequency })
        });
      }
      fetchSubscriptions();
    } catch (e) {
      console.error(e);
    }
  };

  if (loading && !reportData) {
    return (
      <div className="flex flex-col items-center justify-center p-20 text-indigo-400">
        <div className="w-12 h-12 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin mb-4"></div>
        <p className="animate-pulse font-mono tracking-widest uppercase text-xs">Aggregating Global Telemetry...</p>
      </div>
    );
  }

  const maxIpCount = Math.max(...(reportData?.top_ips.map((i: any) => i.count) || [1]));

  return (
    <div className="w-full max-w-6xl mx-auto space-y-8 animate-fade-in">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h2 className="text-3xl font-black text-white tracking-tight flex items-center">
            <BarChart3 className="w-8 h-8 mr-3 text-indigo-400" /> Security Intelligence
          </h2>
          <p className="text-slate-400 text-sm mt-1">Deep analysis of blocked threats and traffic patterns</p>
        </div>
        <div className="flex bg-slate-800/50 p-1 rounded-xl border border-slate-700/50">
          {[1, 7, 30].map(d => (
            <button 
              key={d}
              onClick={() => setDays(d)}
              className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${days === d ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-400 hover:text-white'}`}
            >
              Last {d === 1 ? '24h' : d + ' Days'}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Main Stats */}
        <div className="grid grid-cols-2 gap-4">
           <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-700/50 p-6 rounded-3xl relative overflow-hidden group">
              <div className="absolute -right-4 -bottom-4 w-20 h-20 bg-indigo-500/10 rounded-full blur-2xl group-hover:bg-indigo-500/20 transition-all"></div>
              <Activity className="w-5 h-5 text-indigo-400 mb-4" />
              <div className="text-3xl font-black text-white">{reportData?.total_requests.toLocaleString()}</div>
              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">Total Requests</div>
           </div>
           <div className="bg-slate-900/40 backdrop-blur-xl border border-red-500/20 p-6 rounded-3xl relative overflow-hidden group">
              <div className="absolute -right-4 -bottom-4 w-20 h-20 bg-red-500/10 rounded-full blur-2xl group-hover:bg-red-500/20 transition-all"></div>
              <ShieldAlert className="w-5 h-5 text-red-500 mb-4" />
              <div className="text-3xl font-black text-red-400">{reportData?.total_blocked.toLocaleString()}</div>
              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">Blocked Actions</div>
           </div>

           {/* Email Subscriptions Sub-Panel */}
           <div className="col-span-2 bg-gradient-to-br from-indigo-900/20 to-slate-900/40 backdrop-blur-xl border border-indigo-500/20 p-6 rounded-3xl">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center">
                   <div className="p-2 bg-indigo-500/20 rounded-lg mr-3">
                      <BellRing className="w-4 h-4 text-indigo-400" />
                   </div>
                   <h4 className="text-sm font-bold text-white uppercase tracking-wider">Email Digest Subscriptions</h4>
                </div>
              </div>
              <div className="space-y-3">
                {['daily', 'weekly'].map(freq => {
                   const isSubbed = subscriptions.some(s => s.frequency === freq);
                   return (
                    <div key={freq} onClick={() => toggleSubscription(freq)} className={`flex items-center justify-between p-4 rounded-2xl border cursor-pointer transition-all ${isSubbed ? 'bg-indigo-600/20 border-indigo-500/40 text-white' : 'bg-slate-800/30 border-slate-700/50 text-slate-400 hover:border-slate-600'}`}>
                       <div className="flex items-center">
                          <Calendar className={`w-4 h-4 mr-3 ${isSubbed ? 'text-indigo-400' : 'text-slate-500'}`} />
                          <span className="capitalize font-bold text-sm">{freq} Security Report</span>
                       </div>
                       <div className={`w-10 h-5 rounded-full relative transition-colors ${isSubbed ? 'bg-indigo-500' : 'bg-slate-700'}`}>
                          <div className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all ${isSubbed ? 'left-6' : 'left-1'}`}></div>
                       </div>
                    </div>
                   );
                })}
              </div>
           </div>
        </div>

        {/* Top 5 Attacking IPs - Visual Bar Chart */}
        <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-700/50 p-8 rounded-3xl shadow-2xl">
           <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-8 flex items-center">
             <TrendingUp className="w-4 h-4 mr-2 text-cyan-400" /> Top 5 Attacking Sources
           </h4>
           <div className="space-y-6">
              {reportData?.top_ips.map((item: any, idx: number) => (
                <div key={item.key} className="space-y-2">
                   <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-300">{item.key}</span>
                      <span className="text-indigo-400 font-bold">{item.count} blocks</span>
                   </div>
                   <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-indigo-600 to-cyan-500 rounded-full transition-all duration-1000 shadow-[0_0_10px_rgba(99,102,241,0.5)]"
                        style={{ width: `${(item.count / maxIpCount) * 100}%` }}
                      ></div>
                   </div>
                </div>
              ))}
              {reportData?.top_ips.length === 0 && <div className="text-slate-600 italic text-sm text-center py-10">No attacks recorded in this window.</div>}
           </div>
        </div>

        {/* Block Reasons - Tag Cloud Style */}
        <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-700/50 p-8 rounded-3xl">
           <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-8 flex items-center">
             <ShieldAlert className="w-4 h-4 mr-2 text-red-500" /> Common Block Vectors
           </h4>
           <div className="flex flex-wrap gap-3">
              {reportData?.top_reasons.map((item: any) => (
                <div key={item.key} className="px-4 py-2 bg-red-950/20 border border-red-500/20 rounded-xl flex items-center group hover:bg-red-500/10 hover:border-red-500/40 transition-all">
                   <span className="text-xs font-mono text-red-300 mr-3">{item.key.replace('envoy.', '')}</span>
                   <span className="bg-red-500/20 text-red-400 text-[10px] font-bold px-2 py-0.5 rounded-lg">{item.count}</span>
                </div>
              ))}
           </div>
        </div>

        {/* Status Distribution - Donut Chart (Pure CSS) */}
        <div className="bg-slate-900/40 backdrop-blur-xl border border-slate-700/50 p-8 rounded-3xl flex flex-col items-center">
           <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-8 w-full">
             <PieIcon className="w-4 h-4 mr-2 inline text-orange-400" /> Response Composition
           </h4>
           
           <div className="relative w-40 h-40 mb-6">
              {/* This is a visual representation using layered CSS circles */}
              <div className="absolute inset-0 border-[16px] border-slate-800 rounded-full"></div>
              {/* We calculate rough segments here for visualization */}
              <svg className="w-full h-full -rotate-90">
                 <circle 
                   cx="80" cy="80" r="72" 
                   fill="transparent" 
                   stroke="#22c55e" 
                   strokeWidth="16" 
                   strokeDasharray="452" 
                   strokeDashoffset={452 - (452 * (reportData?.total_requests ? (reportData.total_requests - reportData.total_blocked) / reportData.total_requests : 0))}
                   className="transition-all duration-1000"
                 />
                 <circle 
                   cx="80" cy="80" r="72" 
                   fill="transparent" 
                   stroke="#ef4444" 
                   strokeWidth="16" 
                   strokeDasharray="452" 
                   strokeDashoffset={452 - (452 * (reportData?.total_requests ? reportData.total_blocked / reportData.total_requests : 0))}
                   style={{ transformOrigin: 'center', transform: `rotate(${( (reportData?.total_requests - reportData?.total_blocked) / reportData?.total_requests ) * 360}deg)` }}
                   className="transition-all duration-1000"
                 />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <div className="text-xl font-black text-white">{reportData?.total_requests > 0 ? Math.round(((reportData.total_requests - reportData.total_blocked) / reportData.total_requests) * 100) : 0}%</div>
                  <div className="text-[8px] font-bold text-slate-500 uppercase tracking-widest">Success</div>
              </div>
           </div>

           <div className="grid grid-cols-2 gap-4 w-full px-4">
              <div className="flex items-center space-x-2">
                 <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                 <span className="text-[10px] font-bold text-slate-400">PASSED: {(reportData?.total_requests - reportData?.total_blocked).toLocaleString()}</span>
              </div>
              <div className="flex items-center space-x-2">
                 <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                 <span className="text-[10px] font-bold text-slate-400">BLOCKED: {reportData?.total_blocked.toLocaleString()}</span>
              </div>
           </div>
        </div>
      </div>
    </div>
  );
};

export default ReportsTab;
