import React, { useState, useEffect } from 'react';
import { ClipboardList, ShieldAlert, FileText } from 'lucide-react';

interface AuditLogsTabProps {
  authToken: string;
}

const AuditLogsTab: React.FC<AuditLogsTabProps> = ({ authToken }) => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    try {
      const res = await fetch('http://localhost:8555/api/audit-logs', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (res.ok) {
        setLogs(await res.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [authToken]);

  return (
    <div className="bg-[#1e2333]/80 p-8 rounded-2xl shadow-lg border border-slate-700/60 backdrop-blur-xl min-h-[50vh]">
       <div className="flex items-center justify-between mb-6 border-b border-slate-700/50 pb-4">
          <div className="flex items-center">
             <ClipboardList className="w-8 h-8 mr-3 text-indigo-400" />
             <h2 className="text-2xl font-bold text-white tracking-wide">System Audit Logs</h2>
          </div>
          <button onClick={fetchLogs} className="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm font-semibold transition">
             Refresh
          </button>
       </div>

       {loading ? (
           <div className="text-slate-400 text-center italic py-10">Loading audit history...</div>
       ) : logs.length === 0 ? (
           <div className="text-slate-500 text-center italic p-10 bg-slate-800/40 rounded-xl border border-slate-700/50 backdrop-blur-md">
             No audit logs found.
           </div>
       ) : (
           <div className="overflow-x-auto rounded-xl border border-slate-700">
               <table className="w-full text-left text-sm text-slate-300">
                   <thead className="bg-slate-800 text-slate-400 text-xs uppercase font-semibold">
                       <tr>
                           <th className="px-6 py-3 border-b border-slate-700/50">Timestamp</th>
                           <th className="px-6 py-3 border-b border-slate-700/50">User</th>
                           <th className="px-6 py-3 border-b border-slate-700/50">Action</th>
                           <th className="px-6 py-3 border-b border-slate-700/50">Details</th>
                       </tr>
                   </thead>
                   <tbody className="divide-y divide-slate-700/50 bg-slate-900/50 font-mono text-[13px]">
                       {logs.map((log: any) => (
                           <tr key={log.id} className="hover:bg-slate-800/80 transition-colors">
                               <td className="px-6 py-4 whitespace-nowrap text-slate-400">
                                   {new Date(log.timestamp + "Z").toLocaleString()}
                               </td>
                               <td className="px-6 py-4 font-bold text-indigo-300">
                                   {log.username || 'SYSTEM'}
                               </td>
                               <td className="px-6 py-4">
                                   <span className={`px-2 py-1 rounded text-xs tracking-wider ${
                                       log.action.includes('DELETE') ? 'bg-red-900/50 text-red-400' :
                                       log.action.includes('CREATE') ? 'bg-green-900/50 text-green-400' :
                                       log.action.includes('ALERT') ? 'bg-orange-900/50 text-orange-400' :
                                       'bg-slate-700 text-slate-300'
                                   }`}>
                                       {log.action}
                                   </span>
                               </td>
                               <td className="px-6 py-4 text-slate-400 max-w-md truncate" title={log.details}>
                                   {log.details || '-'}
                               </td>
                           </tr>
                       ))}
                   </tbody>
               </table>
           </div>
       )}
    </div>
  );
};

export default AuditLogsTab;
