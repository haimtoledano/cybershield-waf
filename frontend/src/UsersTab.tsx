import React, { useState, useEffect, useCallback } from 'react';
import { Users, Plus, Trash2, Loader2, Edit2, X, ShieldAlert } from 'lucide-react';
import { api } from './api';

interface User {
  id: string;
  username: string;
  role: 'admin' | 'viewer';
  email: string | null;
  mfa_enabled: boolean;
}

interface Props {
  authToken: string;
}

const UsersTab: React.FC<Props> = ({ authToken }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newRole, setNewRole] = useState<'admin' | 'viewer'>('viewer');
  const [message, setMessage] = useState<{ text: string, type: 'success' | 'error' } | null>(null);

  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [editEmail, setEditEmail] = useState('');
  const [editRole, setEditRole] = useState<'admin' | 'viewer'>('viewer');
  const [resetMfaUri, setResetMfaUri] = useState<string | null>(null);

  const fetchUsers = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await api.get('/api/users');
      if (!response.ok) throw new Error('Failed to fetch');
      const data = await response.json();
      setUsers(data);
    } catch (err: any) {
      setError('Failed to fetch user data. Please check the API endpoint.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const handleDeleteUser = async (id: string, username: string) => {
    if (!window.confirm(`Are you sure you want to delete the user "${username}"?`)) return;

    try {
      const response = await api.delete(`/api/users/${id}`);
      if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || 'Delete failed');
      }
      setMessage({ text: `${username} successfully deleted.`, type: 'success' });
      fetchUsers();
    } catch (err: any) {
      setMessage({ text: `Error deleting user: ${err.message}`, type: 'error' });
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();

    if (newPassword.length < 4) {
      setMessage({ text: 'Password must be at least 4 characters long.', type: 'error' });
      return;
    }

    try {
      const response = await api.post('/api/users', { 
        username: newUsername, 
        password: newPassword, 
        role: newRole, 
        email: newEmail 
      });
      
      if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || 'Creation failed');
      }
      setMessage({ text: `User ${newUsername} created successfully!`, type: 'success' });
      fetchUsers();
      setNewUsername('');
      setNewPassword('');
      setNewEmail('');
      setNewRole('viewer');
    } catch (err: any) {
      setMessage({ text: err.message, type: 'error' });
    }
  };

  const startEdit = (user: User) => {
    setEditingUser(user);
    setEditEmail(user.email || '');
    setEditRole(user.role);
    setResetMfaUri(null);
  };

  const handleUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser) return;
    try {
      const response = await api.put(`/api/users/${editingUser.id}`, { 
        email: editEmail, 
        role: editRole 
      });
      if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || 'Update failed');
      }
      setMessage({ text: `User updated successfully!`, type: 'success' });
      fetchUsers();
      setEditingUser(null);
    } catch (err: any) {
      setMessage({ text: err.message, type: 'error' });
    }
  };

  const handleResetMFA = async () => {
    if (!editingUser) return;
    if (!window.confirm("This will instantly invalidate the user's current MFA codes. Proceed?")) return;
    try {
      const response = await api.post(`/api/users/${editingUser.id}/mfa/reset`);
      if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || 'Reset failed');
      }
      const data = await response.json();
      setResetMfaUri(data.uri);
      setMessage({ text: `MFA reset successfully. QR code generated.`, type: 'success' });
      fetchUsers();
    } catch (err: any) {
      setMessage({ text: err.message, type: 'error' });
    }
  };

  const renderMessage = () => {
    if (!message) return null;
    const typeClasses = message.type === 'success'
      ? 'bg-green-100 border-l-4 border-green-500 text-green-700'
      : 'bg-red-100 border-l-4 border-red-500 text-red-700';

    return (
      <div className={`p-3 rounded-md mb-4 flex items-center ${typeClasses}`}>
        <span className="text-sm">{message.text}</span>
      </div>
    );
  };

  return (
    <div className="p-6 bg-slate-800 shadow-lg rounded-xl flex-1 text-slate-200">
      <h1 className="text-3xl font-bold mb-6 flex items-center">
        <Users className="w-8 h-8 mr-3 text-indigo-400" />
        User Management Dashboard
      </h1>

      {renderMessage()}

      <div className="mb-8 p-6 border border-slate-700 rounded-lg bg-slate-900/50">
        <h2 className="text-xl font-semibold mb-4 flex items-center text-indigo-300">
          <Plus className="w-5 h-5 mr-2" /> Create New User
        </h2>
        <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-6 gap-4 items-end">
          <div className="col-span-2">
            <label className="block text-sm font-medium mb-1">Username</label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-slate-600 bg-slate-800 rounded-md focus:outline-none focus:border-indigo-500"
              required
            />
          </div>
          <div className="col-span-1">
            <label className="block text-sm font-medium mb-1">Email</label>
            <input
              type="email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-slate-600 bg-slate-800 rounded-md focus:outline-none focus:border-indigo-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-slate-600 bg-slate-800 rounded-md focus:outline-none focus:border-indigo-500"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Role</label>
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value as 'admin' | 'viewer')}
              className="mt-1 block w-full px-3 py-2 border border-slate-600 bg-slate-800 rounded-md focus:outline-none focus:border-indigo-500"
            >
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <button
            type="submit"
            className="w-full h-[42px] flex justify-center items-center px-4 border border-transparent rounded-md shadow-sm font-medium text-white bg-indigo-600 hover:bg-indigo-500"
          >
            Create
          </button>
        </form>
      </div>

      <div>
        <h2 className="text-2xl font-bold mb-4">Existing Users</h2>
        {isLoading && !error && (
          <div className="flex justify-center h-48 items-center">
            <Loader2 className="w-8 h-8 mr-3 text-indigo-400 animate-spin" />
            <span>Loading...</span>
          </div>
        )}
        {error && <div className="text-red-400 mb-4">{error}</div>}
        {!isLoading && !error && (
          <div className="overflow-x-auto border border-slate-700 rounded-lg">
            <table className="min-w-full divide-y divide-slate-700">
              <thead className="bg-slate-900/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-400">Username</th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-400">Email</th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-400">Role</th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-400">MFA</th>
                  <th className="px-6 py-3 text-right text-xs font-medium uppercase tracking-wider text-slate-400">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {users.map((user) => (
                  <tr key={user.id} className="hover:bg-slate-700/30">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{user.username}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">{user.email || 'N/A'}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${user.role === 'admin' ? 'bg-red-900/30 text-red-400 border border-red-500/30' : 'bg-blue-900/30 text-blue-400 border border-blue-500/30'}`}>
                        {user.role}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      {user.mfa_enabled ? <span className="text-green-400">Enabled</span> : <span className="text-slate-500">Disabled</span>}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm">
                      <button onClick={() => startEdit(user)} className="text-indigo-400 hover:text-indigo-300 mr-4">
                        <Edit2 className="w-5 h-5 inline" />
                      </button>
                      <button onClick={() => handleDeleteUser(user.id, user.username)} className="text-red-400 hover:text-red-300">
                        <Trash2 className="w-5 h-5 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Editing Modal */}
      {editingUser && (
        <div className="fixed inset-0 backdrop-blur-md bg-black/60 flex justify-center items-center z-50">
          <div className="bg-slate-900 border border-slate-700 p-8 rounded-2xl shadow-2xl w-full max-w-lg relative">
            <button onClick={() => setEditingUser(null)} className="absolute top-4 right-4 text-slate-400 hover:text-white transition">
              <X className="w-6 h-6" />
            </button>
            <h2 className="text-2xl font-bold mb-6 flex items-center">
              <Edit2 className="w-6 h-6 mr-3 text-indigo-400" />
              Edit User Settings
            </h2>
            <div className="bg-slate-800/80 p-4 rounded-lg border border-slate-700 mb-6">
              <p className="text-slate-300"><span className="font-semibold">Username:</span> {editingUser.username}</p>
            </div>
            
            <form onSubmit={handleUpdateUser} className="space-y-4 mb-8">
              <div>
                <label className="block text-sm font-medium mb-1">Email</label>
                <input
                  type="email"
                  value={editEmail}
                  onChange={(e) => setEditEmail(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-600 bg-slate-800 rounded-md focus:outline-none focus:border-indigo-500 text-white"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Role</label>
                <select
                  value={editRole}
                  onChange={(e) => setEditRole(e.target.value as 'admin'|'viewer')}
                  className="w-full px-3 py-2 border border-slate-600 bg-slate-800 rounded-md focus:outline-none focus:border-indigo-500 text-white"
                >
                  <option value="viewer">Viewer</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <button type="submit" className="w-full bg-indigo-600 hover:bg-indigo-500 text-white p-2 rounded-lg font-semibold transition">
                Save Changes
              </button>
            </form>

            <div className="border-t border-slate-700 pt-6">
              <h3 className="text-lg font-semibold mb-2 flex items-center text-red-400">
                <ShieldAlert className="w-5 h-5 mr-2" /> Security Actions
              </h3>
              <p className="text-xs text-slate-400 mb-4">Resetting MFA will invalidate the user's current authenticator app.</p>
              
              {!resetMfaUri ? (
                <button onClick={handleResetMFA} className="flex justify-center items-center w-full bg-slate-800 hover:bg-red-900/40 text-red-400 border border-red-500/30 p-2 rounded-lg transition font-medium">
                  Verify & Reset MFA Device
                </button>
              ) : (
                <div className="flex flex-col items-center bg-white p-6 rounded-xl mt-4">
                  <h4 className="text-black font-bold mb-2">New QR Code Generated</h4>
                  <img src={`https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(resetMfaUri)}`} alt="New MFA QR" className="w-48 h-48 mb-2" />
                  <p className="text-slate-600 text-xs text-center">Take a screenshot or show this to the user immediately.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default UsersTab;
