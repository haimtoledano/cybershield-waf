import React, { useState, useCallback } from 'react';
import { Mail, Key, Loader2, AlertTriangle } from 'lucide-react';
import { QRCodeCanvas } from 'qrcode.react';

interface LoginViewProps {
  mfaRequired?: boolean;
  errorMsg?: string | null;
  onLogin: (user: string, pass: string, mfaCode?: string) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ mfaRequired, errorMsg, onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (password.length < 4) {
      alert('Password must be at least 4 characters long.');
      return;
    }

    setIsLoading(true);
    onLogin(username, password, mfaRequired ? mfaCode : undefined);
    
    // reset loader if it comes back
    setTimeout(() => setIsLoading(false), 2000);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 p-4">
      <div className="w-full max-w-md bg-slate-800 p-8 rounded-xl shadow-2xl border border-slate-700">
        <div className="text-center mb-10 flex flex-col items-center">
          <img src="/luminawaf_logo.png" alt="LuminaWAF Logo" className="h-20 w-20 mb-4 object-contain shadow-indigo-500/50 drop-shadow-[0_0_15px_rgba(79,70,229,0.5)] rounded-2xl" />
          <h1 className="text-3xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-300">LuminaWAF</h1>
          <p className="text-slate-400 mt-2 font-mono text-sm uppercase tracking-widest">Control Plane Login</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1 flex items-center">
              <Mail className="w-4 h-4 mr-2 text-indigo-400" /> Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full p-3 bg-slate-900 border border-slate-700 text-white rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1 flex items-center">
              <Key className="w-4 h-4 mr-2 text-indigo-400" /> Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full p-3 bg-slate-900 border border-slate-700 text-white rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
              placeholder="Min 4 characters"
              required
            />
          </div>

          {mfaRequired && (
            <div className="pt-4 border-t border-slate-700">
              <label className="block text-sm font-medium text-slate-300 mb-1 flex items-center">
                MFA Authenticator Code
              </label>
              <input
                type="text"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                maxLength={6}
                className="w-full p-3 bg-slate-900 border border-slate-700 text-white rounded-lg focus:ring-indigo-500 tracking-widest text-center text-lg"
                placeholder="Enter 6-digit code"
                required
              />
            </div>
          )}

          {errorMsg && (
            <div className="flex items-center p-3 bg-red-900/30 border border-red-500/50 text-red-400 rounded-lg">
              <AlertTriangle className="w-5 h-5 mr-2" />
              <span>{errorMsg}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className={`w-full flex justify-center items-center py-3 px-4 rounded-lg font-medium ${
              isLoading ? 'bg-indigo-500/50 cursor-not-allowed text-white' : 'bg-indigo-600 hover:bg-indigo-500 text-white'
            }`}
          >
            {isLoading ? <Loader2 className="mr-2 h-5 w-5 animate-spin" /> : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
};

interface MFASetupViewProps {
  setupUri: string;
  onVerify: (code: string) => void;
}

export const MFASetupView: React.FC<MFASetupViewProps> = ({ setupUri, onVerify }) => {
  const [verificationCode, setVerificationCode] = useState('');

  const handleVerify = (e: React.FormEvent) => {
    e.preventDefault();
    onVerify(verificationCode);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 p-4">
      <div className="w-full max-w-lg bg-slate-800 p-8 rounded-xl shadow-2xl border border-slate-700 space-y-8">
        <div className="text-center flex flex-col items-center">
          <img src="/luminawaf_logo.png" alt="LuminaWAF Logo" className="h-16 w-16 mb-4 object-contain shadow-indigo-500/50 drop-shadow-[0_0_15px_rgba(79,70,229,0.5)] rounded-2xl" />
          <h2 className="text-3xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-300 mb-2">2FA Setup Required</h2>
          <p className="text-slate-400">Scan the QR code with your authenticator app to enable Two-Factor Authentication.</p>
        </div>

        <div className="bg-white p-6 rounded-lg flex justify-center items-center shadow-inner mx-auto w-fit">
          <QRCodeCanvas value={setupUri} size={256} level="H" />
        </div>

        <div className="space-y-6">
          <div className="space-y-2">
            <label className="block text-sm font-medium text-slate-300 text-center">
              Enter the verification code from your App:
            </label>
            <input
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value)}
                autoFocus
                className="w-full p-4 bg-slate-900 border border-slate-700 text-white rounded-lg text-center text-3xl focus:ring-indigo-500 tracking-widest"
                maxLength={6}
                required
            />
          </div>

          <button
            type="button"
            onClick={handleVerify}
            className="w-full flex justify-center items-center py-3 px-4 rounded-lg font-medium bg-indigo-600 hover:bg-indigo-500 text-white"
          >
            Verify and Activate
          </button>
        </div>
      </div>
    </div>
  );
};
