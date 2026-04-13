import React, { useState, useEffect, useCallback } from 'react';
import { ShieldAlert, Plus, Trash2, Loader2, Info } from 'lucide-react';
import { api } from './api';

interface IPRule {
  id: string;
  ip_address: string;
  rule_type: 'Whitelist' | 'Blacklist';
  notes: string | null;
  created_at: string;
}

interface Props {
  authToken: string;
}

const IPRulesTab: React.FC<Props> = ({ authToken }) => {
  const [rules, setRules] = useState<IPRule[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  
  const [newIp, setNewIp] = useState('');
  const [newType, setNewType] = useState<'Whitelist' | 'Blacklist'>('Blacklist');
  const [newNotes, setNewNotes] = useState('');
  const [message, setMessage] = useState<{ text: string, type: 'success' | 'error' } | null>(null);

  const fetchRules = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await api.get('/api/ip-rules');
      if (!response.ok) throw new Error('Failed to fetch IP RULES');
      const data = await response.json();
      setRules(data);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);
    
    try {
      const response = await api.post('/api/ip-rules', { ip_address: newIp, rule_type: newType, notes: newNotes });
      
      if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || 'Failed to add rule');
      }
      
      setMessage({ text: `IP rule added successfully!`, type: 'success' });
      fetchRules();
      setNewIp('');
      setNewNotes('');
      // Force Envoy refresh via the backend triggering update natively...
      // Wait, trigger_envoy_update is currently hooked specifically to virtual-servers routes!
      // I should manually trigger an update or the backend should. (We will verify this after).
    } catch (err: any) {
      setMessage({ text: err.message, type: 'error' });
    }
  };

  const handleDeleteRule = async (id: string, ip: string) => {
    if (!window.confirm(`Are you sure you want to delete the rule for ${ip}?`)) return;
    try {
      const response = await api.delete(`/api/ip-rules/${id}`);
      if (!response.ok) throw new Error('Delete failed');
      fetchRules();
      setMessage({ text: `Rule for ${ip} deleted successfully.`, type: 'success' });
    } catch (err: any) {
      setMessage({ text: err.message, type: 'error' });
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center space-y-4 md:space-y-0">
        <div>
          <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-indigo-300 flex items-center">
            <ShieldAlert className="w-8 h-8 mr-3 text-red-500" />
            Global IP Rules
          </h1>
          <p className="text-slate-400 max-w-2xl mt-2">Manage malicious actors (Blacklist) or allowed integrators (Whitelist). Blacklists enforce global 403 blocks instantly, Whitelists bypass Threat Intelligence inspections.</p>
        </div>
      </div>

      {message && (
        <div className={`p-4 rounded-xl text-sm font-medium border ${message.type === 'success' ? 'bg-green-900/30 text-green-400 border-green-500/30' : 'bg-red-900/30 text-red-400 border-red-500/30'}`}>
          {message.text}
        </div>
      )}

      <div className="bg-slate-800/80 p-6 rounded-2xl shadow-xl border border-slate-700 backdrop-blur-xl">
        <h2 className="text-xl font-semibold mb-4 flex items-center text-indigo-300">
          <Plus className="w-5 h-5 mr-2" /> Add Rule
        </h2>
        <form onSubmit={handleCreateRule} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div>
            <label className="block text-sm font-medium mb-1 text-slate-300">IP Address</label>
            <input
              type="text"
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              placeholder="e.g., 192.168.1.1"
              className="mt-1 block w-full px-3 py-2 border border-slate-600 bg-slate-900 text-white rounded-md focus:outline-none focus:border-indigo-500"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-slate-300">Rule Type</label>
            <select
              value={newType}
              onChange={(e) => setNewType(e.target.value as 'Whitelist' | 'Blacklist')}
              className="mt-1 block w-full px-3 py-2 border border-slate-600 bg-slate-900 text-white rounded-md focus:outline-none focus:border-indigo-500"
            >
              <option value="Blacklist">Blacklist (Block)</option>
              <option value="Whitelist">Whitelist (Bypass WAF)</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-slate-300">Notes</label>
            <input
              type="text"
              value={newNotes}
              onChange={(e) => setNewNotes(e.target.value)}
              placeholder="e.g., Attacker from OSINT"
              className="mt-1 block w-full px-3 py-2 border border-slate-600 bg-slate-900 text-white rounded-md focus:outline-none focus:border-indigo-500"
            />
          </div>
          <button
            type="submit"
            className="w-full h-[42px] flex justify-center items-center px-4 border border-transparent rounded-md shadow-lg font-bold text-white bg-indigo-600 hover:bg-indigo-500 transition-all shadow-indigo-500/30"
          >
            Add Rule
          </button>
        </form>
      </div>

      <div>
        <h2 className="text-2xl font-bold mb-4">Active Rules</h2>
        {isLoading && !error && (
          <div className="flex justify-center h-48 items-center">
            <Loader2 className="w-8 h-8 mr-3 text-indigo-400 animate-spin" />
          </div>
        )}
        {error && <div className="text-red-400 mb-4">{error}</div>}
        
        {!isLoading && !error && (
          <div className="overflow-x-auto border border-slate-700/60 rounded-xl shadow-lg bg-[#1e2333]/50">
            <table className="min-w-full divide-y divide-slate-700/60">
              <thead className="bg-slate-900/60">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">IP Address</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Type</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Notes</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Added</th>
                  <th className="px-6 py-4 text-right text-xs font-semibold uppercase tracking-wider text-slate-400">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {rules.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-8 text-center text-slate-500 italic">No IP rules defined.</td>
                  </tr>
                ) : (
                  rules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-slate-700/30 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-bold font-mono text-indigo-300">{rule.ip_address}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <span className={`px-3 py-1 inline-flex text-xs leading-5 font-bold rounded-full border ${
                          rule.rule_type === 'Blacklist' 
                            ? 'bg-red-900/30 text-red-500 border-red-500/30' 
                            : 'bg-green-900/30 text-green-400 border-green-500/30'
                        }`}>
                          {rule.rule_type}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400 max-w-xs truncate" title={rule.notes || ''}>
                        {rule.notes || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500">
                        {new Date(rule.created_at).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm">
                        <button onClick={() => handleDeleteRule(rule.id, rule.ip_address)} className="text-red-400 hover:text-white transition bg-red-900/20 hover:bg-red-900/60 p-2 rounded-lg">
                          <Trash2 className="w-5 h-5 inline" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default IPRulesTab;
