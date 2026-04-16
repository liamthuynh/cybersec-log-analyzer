'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { login, register } from '@/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegister, setIsRegister] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isRegister) {
        await register(username, password);
      } else {
        await login(username, password);
      }
      router.push('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 relative overflow-hidden">
      {/* Background grid effect */}
      <div className="absolute inset-0 opacity-5">
        <div
          className="w-full h-full"
          style={{
            backgroundImage:
              'linear-gradient(rgba(0,212,255,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.3) 1px, transparent 1px)',
            backgroundSize: '40px 40px',
          }}
        />
      </div>

      <div className="w-full max-w-md relative z-10 animate-fade-in">
        {/* Logo / Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyber-accent/10 border border-cyber-accent/30 mb-4">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">
            <span className="text-cyber-accent">Cyber</span>Scope
          </h1>
          <p className="text-cyber-muted mt-2 text-sm">
            AI-Powered Log Analysis for SOC Analysts
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-cyber-card rounded-xl border border-cyber-border p-8 shadow-2xl shadow-black/50">
          <h2 className="text-lg font-semibold mb-6">
            {isRegister ? 'Create Account' : 'Sign In'}
          </h2>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm text-cyber-muted mb-1.5">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg bg-cyber-bg border border-cyber-border
                           text-cyber-text placeholder-cyber-muted/50
                           focus:outline-none focus:border-cyber-accent/50 focus:ring-1 focus:ring-cyber-accent/30
                           transition-all font-mono text-sm"
                placeholder="Enter username"
                required
              />
            </div>
            <div>
              <label className="block text-sm text-cyber-muted mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg bg-cyber-bg border border-cyber-border
                           text-cyber-text placeholder-cyber-muted/50
                           focus:outline-none focus:border-cyber-accent/50 focus:ring-1 focus:ring-cyber-accent/30
                           transition-all font-mono text-sm"
                placeholder="Enter password"
                required
                minLength={6}
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 rounded-lg font-medium text-sm
                         bg-cyber-accent text-cyber-bg
                         hover:bg-cyber-accent/90
                         disabled:opacity-50 disabled:cursor-not-allowed
                         transition-all duration-200"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  {isRegister ? 'Creating...' : 'Signing in...'}
                </span>
              ) : (
                isRegister ? 'Create Account' : 'Sign In'
              )}
            </button>
          </form>

          <div className="mt-6 pt-4 border-t border-cyber-border text-center">
            <button
              onClick={() => { setIsRegister(!isRegister); setError(''); }}
              className="text-sm text-cyber-accent hover:text-cyber-accent/80 transition-colors"
            >
              {isRegister
                ? 'Already have an account? Sign in'
                : "Don't have an account? Register"}
            </button>
          </div>

          {/* Demo credentials hint */}
          {!isRegister && (
            <div className="mt-4 p-3 rounded-lg bg-cyber-accent/5 border border-cyber-accent/20 text-xs text-cyber-muted">
              <span className="text-cyber-accent font-medium">Demo:</span>{' '}
              username <code className="text-cyber-text">demo</code> / password{' '}
              <code className="text-cyber-text">demo1234</code>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
