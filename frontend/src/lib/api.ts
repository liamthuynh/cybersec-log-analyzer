/**
 * API Client for the Cybersecurity Log Analyzer backend.
 *
 * All calls go through the Next.js rewrite proxy (/api/* → backend API)
 * so the browser stays same-origin in both local and Docker flows.
 */

const API_BASE = '/api';

// ---------- Types ----------

export interface AuthResponse {
  token: string;
  username: string;
}

export interface UploadSummary {
  id: string;
  filename: string;
  upload_time: string;
  status: string;
  total_entries: number;
  anomaly_count: number;
}

export interface Anomaly {
  line_number: number;
  entry: Record<string, any>;
  rule: string;
  reason: string;
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface TimelineBucket {
  time: string;
  total: number;
  errors: number;
  blocked: number;
}

export interface Statistics {
  total_entries: number;
  unique_ips: number;
  unique_users: number;
  total_bytes: number;
  status_codes: Record<string, number>;
  actions: Record<string, number>;
  categories: Record<string, number>;
  methods: Record<string, number>;
  top_domains: { domain: string; count: number }[];
  top_ips: { ip: string; count: number }[];
  severity_breakdown: Record<string, number>;
  anomaly_count: number;
}

export interface AISummary {
  available?: boolean;
  executive_summary?: string;
  threat_level?: string;
  key_findings?: {
    title: string;
    description: string;
    severity: string;
    affected_entities?: string[];
    recommendation?: string;
  }[];
  timeline?: {
    time: string;
    event: string;
    significance: string;
  }[];
  patterns_detected?: string[];
  recommended_actions?: string[];
  error?: string;
  suggestion?: string;
  fallback_summary?: any;
}

export interface AnalysisResult {
  upload_id: string;
  filename: string;
  total_entries: number;
  anomaly_count: number;
  analysis: {
    anomalies: Anomaly[];
    statistics: Statistics;
    timeline: TimelineBucket[];
  };
  ai_summary: AISummary | null;
}

export interface UploadDetail {
  id: string;
  filename: string;
  upload_time: string;
  status: string;
  total_entries: number;
  anomaly_count: number;
  analysis: {
    anomalies: Anomaly[];
    statistics: Statistics;
    timeline: TimelineBucket[];
  };
  ai_summary: AISummary | null;
}

// ---------- Helpers ----------

function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('auth_token');
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return res.json();
}

// ---------- Auth ----------

export async function login(username: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = await handleResponse<AuthResponse>(res);
  localStorage.setItem('auth_token', data.token);
  localStorage.setItem('username', data.username);
  return data;
}

export async function register(username: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = await handleResponse<AuthResponse>(res);
  localStorage.setItem('auth_token', data.token);
  localStorage.setItem('username', data.username);
  return data;
}

export function logout(): void {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('username');
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

export function getUsername(): string {
  return localStorage.getItem('username') || '';
}

// ---------- Uploads ----------

export async function uploadLogFile(file: File, useAI: boolean = true): Promise<AnalysisResult> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('use_ai', useAI ? 'true' : 'false');

  const res = await fetch(`${API_BASE}/upload`, {
    method: 'POST',
    headers: authHeaders(),
    body: formData,
  });
  return handleResponse<AnalysisResult>(res);
}

export async function listUploads(): Promise<UploadSummary[]> {
  const res = await fetch(`${API_BASE}/uploads`, {
    headers: authHeaders(),
  });
  return handleResponse<UploadSummary[]>(res);
}

export async function getUploadDetails(uploadId: string): Promise<UploadDetail> {
  const res = await fetch(`${API_BASE}/uploads/${uploadId}`, {
    headers: authHeaders(),
  });
  return handleResponse<UploadDetail>(res);
}
