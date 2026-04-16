'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  isAuthenticated,
  getUsername,
  logout,
  uploadLogFile,
  listUploads,
  getUploadDetails,
  AnalysisResult,
  UploadDetail,
  UploadSummary,
} from '@/lib/api';
import StatsCards from '@/components/StatsCards';
import TimelineChart from '@/components/TimelineChart';
import AnomalyTable from '@/components/AnomalyTable';
import AISummaryPanel from '@/components/AISummaryPanel';
import UploadHistory from '@/components/UploadHistory';

export default function DashboardPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<UploadSummary[]>([]);
  const [useAI, setUseAI] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'anomalies' | 'ai'>('overview');
  const [loadingUploadId, setLoadingUploadId] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated()) {
      router.push('/login');
      return;
    }
    setUsername(getUsername());
    loadHistory();
  }, [router]);

  const loadHistory = async () => {
    try {
      const data = await listUploads();
      setHistory(data);
    } catch { }
  };

  const handleSelectUpload = async (id: string) => {
    setLoadingUploadId(id);
    setError('');
    try {
      const data: UploadDetail = await getUploadDetails(id);
      // Normalize the response shape to match AnalysisResult
      setResult({
        upload_id: data.id,
        filename: data.filename,
        total_entries: data.total_entries,
        anomaly_count: data.anomaly_count,
        analysis: data.analysis,
        ai_summary: data.ai_summary,
      });
      setActiveTab('overview');
    } catch (err: any) {
      setError(err.message || 'Failed to load upload');
    } finally {
      setLoadingUploadId(null);
    }
  };

  const handleUpload = useCallback(async (file: File) => {
    setError('');
    setUploading(true);
    setResult(null);
    setUploadProgress('Uploading file...');

    try {
      setUploadProgress('Parsing log entries...');
      await new Promise((r) => setTimeout(r, 300));
      setUploadProgress('Running anomaly detection...');

      const data = await uploadLogFile(file, useAI);

      setUploadProgress('Analysis complete!');
      setResult(data);
      setActiveTab('overview');
      loadHistory();
    } catch (err: any) {
      setError(err.message || 'Upload failed');
    } finally {
      setUploading(false);
      setUploadProgress('');
    }
  }, [useAI]);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleUpload(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleUpload(file);
  };

  const handleLogout = () => {
    logout();
    router.push('/login');
  };

  return (
    <div className="min-h-screen bg-cyber-bg">
      {/* Header */}
      <header className="border-b border-cyber-border bg-cyber-surface/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 flex items-center justify-center">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span className="font-semibold text-sm tracking-tight">
              <span className="text-cyber-accent">Cyber</span>Scope
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-cyber-muted font-mono">
              {username}
            </span>
            <button
              onClick={handleLogout}
              className="text-xs text-cyber-muted hover:text-cyber-text transition-colors"
            >
              Sign Out
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Upload Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Upload Zone */}
          <div className="lg:col-span-2">
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              className={`relative rounded-xl border-2 border-dashed p-8 text-center transition-all duration-200 ${
                dragOver
                  ? 'border-cyber-accent bg-cyber-accent/5'
                  : 'border-cyber-border hover:border-cyber-border/80 bg-cyber-card/50'
              }`}
            >
              {uploading ? (
                <div className="space-y-3">
                  <div className="w-10 h-10 mx-auto border-2 border-cyber-accent border-t-transparent rounded-full animate-spin" />
                  <p className="text-sm text-cyber-accent font-mono">{uploadProgress}</p>
                </div>
              ) : (
                <>
                  <svg className="w-10 h-10 mx-auto text-cyber-muted mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                  </svg>
                  <p className="text-sm text-cyber-text mb-1">
                    Drop a log file here or{' '}
                    <label className="text-cyber-accent cursor-pointer hover:underline">
                      browse
                      <input
                        type="file"
                        accept=".txt,.log,.csv"
                        onChange={handleFileInput}
                        className="hidden"
                      />
                    </label>
                  </p>
                  <p className="text-xs text-cyber-muted">
                    Supports .txt, .log, .csv — Max 16MB
                  </p>
                </>
              )}
            </div>

            {/* AI Toggle */}
            <div className="flex items-center gap-2 mt-3">
              <button
                onClick={() => setUseAI(!useAI)}
                className={`relative w-9 h-5 rounded-full transition-colors ${
                  useAI ? 'bg-cyber-accent' : 'bg-cyber-border'
                }`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                    useAI ? 'translate-x-4' : ''
                  }`}
                />
              </button>
              <span className="text-xs text-cyber-muted">
                AI-powered analysis {useAI ? '(on)' : '(off)'}
                {useAI && <span className="text-cyber-accent/60 ml-1">— requires ANTHROPIC_API_KEY</span>}
              </span>
            </div>

            {error && (
              <div className="mt-3 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                {error}
              </div>
            )}
          </div>

          {/* Upload History */}
          <UploadHistory history={history} onSelect={handleSelectUpload} loadingId={loadingUploadId} />
        </div>

        {/* Results */}
        {result && (
          <div className="space-y-6 animate-fade-in">
            {/* Stats Cards */}
            <StatsCards
              stats={result.analysis.statistics}
              anomalyCount={result.anomaly_count}
            />

            {/* Tabs */}
            <div className="border-b border-cyber-border">
              <nav className="flex gap-6">
                {(['overview', 'anomalies', 'ai'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
                      activeTab === tab
                        ? 'border-cyber-accent text-cyber-accent'
                        : 'border-transparent text-cyber-muted hover:text-cyber-text'
                    }`}
                  >
                    {tab === 'overview' && 'Timeline & Overview'}
                    {tab === 'anomalies' && `Anomalies (${result.anomaly_count})`}
                    {tab === 'ai' && 'AI Analysis'}
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab Content */}
            {activeTab === 'overview' && (
              <TimelineChart
                timeline={result.analysis.timeline}
                stats={result.analysis.statistics}
              />
            )}
            {activeTab === 'anomalies' && (
              <AnomalyTable anomalies={result.analysis.anomalies} />
            )}
            {activeTab === 'ai' && (
              <AISummaryPanel aiSummary={result.ai_summary} />
            )}
          </div>
        )}
      </main>
    </div>
  );
}
