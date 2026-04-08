import React, { useState, useEffect } from 'react';
import { Settings, Save, Server, Globe, Mail } from 'lucide-react';

interface SettingsTabProps {
  authToken: string;
}

const SettingsTab: React.FC<SettingsTabProps> = ({ authToken }) => {
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [saveStatus, setSaveStatus] = useState<string | null>(null);

  const fetchSettings = async () => {
    try {
      const res = await fetch('http://localhost:8555/api/settings', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        const settingsMap: Record<string, string> = {};
        data.forEach((s: any) => {
           settingsMap[s.setting_key] = s.setting_value || '';
        });
        setSettings({
            ddos_blacklist_ttl_minutes: settingsMap.ddos_blacklist_ttl_minutes || '10',
            syslog_host: settingsMap.syslog_host || '',
            syslog_port: settingsMap.syslog_port || '514',
            smtp_host: settingsMap.smtp_host || '',
            smtp_port: settingsMap.smtp_port || '587',
            smtp_user: settingsMap.smtp_user || '',
            smtp_password: settingsMap.smtp_password || '',
            admin_email: settingsMap.admin_email || '',
        });
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, [authToken]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setSaveStatus(null);
    try {
      const res = await fetch('http://localhost:8555/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify(settings)
      });
      if (!res.ok) throw new Error("Failed to save settings");
      setSaveStatus("success");
      setTimeout(() => setSaveStatus(null), 3000);
    } catch (e: any) {
      setSaveStatus("Error: " + e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      setSettings({ ...settings, [e.target.name]: e.target.value });
  };

  return (
    <div className="bg-[#1e2333]/80 p-8 rounded-2xl shadow-lg border border-slate-700/60 backdrop-blur-xl">
       <div className="flex items-center mb-6 border-b border-slate-700/50 pb-4">
          <Settings className="w-8 h-8 mr-3 text-indigo-400" />
          <h2 className="text-2xl font-bold text-white tracking-wide">Global System Configuration</h2>
       </div>

       <form onSubmit={handleSave} className="space-y-8">
          
          {/* Threat Intelligence / DDoS settings */}
          <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
             <h3 className="text-lg font-bold text-white mb-4 flex items-center border-b border-slate-700 pb-2">
                <Globe className="w-5 h-5 mr-2 text-indigo-400" /> Rate Limiting & Threat Intelligence
             </h3>
             <div className="grid grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Blacklist TTL (Minutes)</label>
                  <input type="number" name="ddos_blacklist_ttl_minutes" min="1" max="1440" value={settings.ddos_blacklist_ttl_minutes || ''} onChange={handleChange} className="w-full bg-slate-900 border border-slate-600 text-white p-3 rounded-lg outline-none focus:border-indigo-500" placeholder="e.g. 10" />
                  <p className="text-slate-500 text-xs mt-2">Duration an IP remains in the Blacklist after being blocked by DDoS rate limiters.</p>
                </div>
             </div>
          </div>

          {/* Syslog Forwarding */}
          <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
             <h3 className="text-lg font-bold text-white mb-4 flex items-center border-b border-slate-700 pb-2">
                <Server className="w-5 h-5 mr-2 text-indigo-400" /> Syslog Forwarding (UDP)
             </h3>
             <div className="grid grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Syslog Host / IP</label>
                  <input type="text" name="syslog_host" value={settings.syslog_host || ''} onChange={handleChange} className="w-full bg-slate-900 border border-slate-600 text-white p-3 rounded-lg outline-none focus:border-indigo-500" placeholder="e.g. 192.168.1.100" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Syslog Port</label>
                  <input type="number" name="syslog_port" value={settings.syslog_port || ''} onChange={handleChange} className="w-full bg-slate-900 border border-slate-600 text-white p-3 rounded-lg outline-none focus:border-indigo-500" placeholder="e.g. 514" />
                </div>
             </div>
             <p className="text-slate-500 text-xs mt-3">If configured, traffic logs will be forwarded out of the cluster as JSON over standard UDP syslog.</p>
          </div>

          {/* Email / SMTP settings */}
          <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
             <h3 className="text-lg font-bold text-white mb-4 flex items-center border-b border-slate-700 pb-2">
                <Mail className="w-5 h-5 mr-2 text-indigo-400" /> SMTP Alerts
             </h3>
             <p className="text-slate-400 text-xs mb-4">Emails will be dispatched to the admin email when a Virtual Server is deactivated due to a severe DDoS attack.</p>
             <div className="grid grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">SMTP Host</label>
                  <input type="text" name="smtp_host" value={settings.smtp_host || ''} onChange={handleChange} className="w-full bg-slate-900 border border-slate-600 text-white p-3 rounded-lg outline-none focus:border-indigo-500" placeholder="e.g. smtp.gmail.com" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">SMTP Port</label>
                  <input type="number" name="smtp_port" value={settings.smtp_port || ''} onChange={handleChange} className="w-full bg-slate-900 border border-slate-600 text-white p-3 rounded-lg outline-none focus:border-indigo-500" placeholder="e.g. 587" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">SMTP Username</label>
                  <input type="text" name="smtp_user" value={settings.smtp_user || ''} onChange={handleChange} className="w-full bg-slate-900 border border-slate-600 text-white p-3 rounded-lg outline-none focus:border-indigo-500" placeholder="e.g. admin@domain.com" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">SMTP Password (App Password)</label>
                  <input type="password" name="smtp_password" value={settings.smtp_password || ''} onChange={handleChange} className="w-full bg-slate-900 border border-slate-600 text-white p-3 rounded-lg outline-none focus:border-indigo-500" placeholder="•••••••••" />
                </div>
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-slate-300 mb-1">Target Administrator Email</label>
                  <input type="email" name="admin_email" value={settings.admin_email || ''} onChange={handleChange} className="w-full bg-slate-900 border border-slate-600 text-white p-3 rounded-lg outline-none focus:border-indigo-500" placeholder="e.g. security@domain.com" />
                </div>
             </div>
          </div>

          <div className="flex items-center space-x-4">
             <button type="submit" disabled={loading} className="flex items-center bg-indigo-600 hover:bg-indigo-500 font-bold text-white px-6 py-3 rounded-xl transition shadow-[0_0_15px_rgba(79,70,229,0.4)]">
                 <Save className="w-5 h-5 mr-2" />
                 {loading ? "Saving..." : "Save Configuration"}
             </button>
             {saveStatus === 'success' && <div className="text-green-400 font-bold">Successfully saved settings!</div>}
             {saveStatus && saveStatus.startsWith('Error') && <div className="text-red-400 font-bold">{saveStatus}</div>}
          </div>
       </form>
    </div>
  );
};

export default SettingsTab;
