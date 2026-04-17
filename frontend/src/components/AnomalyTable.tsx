'use client';

import { useState, Fragment } from 'react';
import { Anomaly } from '@/lib/api';

interface Props {
  anomalies: Anomaly[];
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
  }[severity] || 'badge-low';

  return <span className={`badge ${cls}`}>{severity.toUpperCase()}</span>;
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100);
  const color =
    pct >= 80 ? 'bg-red-500' :
    pct >= 60 ? 'bg-orange-500' :
    pct >= 40 ? 'bg-yellow-500' : 'bg-green-500';

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-cyber-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-cyber-muted">{pct}%</span>
    </div>
  );
}

export default function AnomalyTable({ anomalies }: Props) {
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [filter, setFilter] = useState<string>('all');

  const filtered = filter === 'all'
    ? anomalies
    : anomalies.filter((a) => a.severity === filter);

  return (
    <div className="bg-cyber-card rounded-xl border border-cyber-border overflow-hidden">
      {/* Toolbar */}
      <div className="px-5 py-3 border-b border-cyber-border flex items-center justify-between">
        <h3 className="text-sm font-semibold">
          Detected Anomalies
          <span className="text-cyber-muted font-normal ml-2">({filtered.length})</span>
        </h3>
        <div className="flex gap-1">
          {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                filter === f
                  ? 'bg-cyber-accent/20 text-cyber-accent'
                  : 'text-cyber-muted hover:text-cyber-text'
              }`}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-cyber-muted border-b border-cyber-border">
              <th className="text-left px-5 py-2.5 font-medium">Severity</th>
              <th className="text-left px-5 py-2.5 font-medium">Rule</th>
              <th className="text-left px-5 py-2.5 font-medium">Source IP</th>
              <th className="text-left px-5 py-2.5 font-medium">Timestamp</th>
              <th className="text-left px-5 py-2.5 font-medium">Confidence</th>
              <th className="text-left px-5 py-2.5 font-medium w-8"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((anomaly, idx) => (
              <Fragment key={idx}>
                <tr
                  onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                  className="border-b border-cyber-border/50 hover:bg-cyber-bg/50 cursor-pointer transition-colors"
                >
                  <td className="px-5 py-3">
                    <SeverityBadge severity={anomaly.severity} />
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-cyber-text">
                    {anomaly.rule.split(',')[0]}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-cyber-accent">
                    {anomaly.entry?.source_ip || '—'}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-cyber-muted">
                    {anomaly.entry?.timestamp
                      ? new Date(anomaly.entry.timestamp).toLocaleString()
                      : '—'}
                  </td>
                  <td className="px-5 py-3">
                    <ConfidenceBar confidence={anomaly.confidence} />
                  </td>
                  <td className="px-5 py-3 text-cyber-muted">
                    <svg
                      width="14"
                      height="14"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      className={`transition-transform ${expandedRow === idx ? 'rotate-180' : ''}`}
                    >
                      <polyline points="6 9 12 15 18 9" />
                    </svg>
                  </td>
                </tr>
                {expandedRow === idx && (
                  <tr className="bg-cyber-bg/30">
                    <td colSpan={6} className="px-5 py-4">
                      <div className="space-y-3">
                        {/* Reason */}
                        <div>
                          <div className="text-xs text-cyber-muted mb-1">Why this was flagged:</div>
                          <div className="text-sm text-yellow-300/90 bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-3 font-mono text-xs leading-relaxed">
                            {anomaly.reason}
                          </div>
                        </div>
                        {/* Entry Details */}
                        <div>
                          <div className="text-xs text-cyber-muted mb-1">Log Entry Details:</div>
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                            {anomaly.entry?.method && (
                              <div>
                                <span className="text-cyber-muted">Method: </span>
                                <span className="font-mono text-cyber-text">{anomaly.entry.method}</span>
                              </div>
                            )}
                            {anomaly.entry?.url && (
                              <div className="col-span-2">
                                <span className="text-cyber-muted">URL: </span>
                                <span className="font-mono text-cyber-accent break-all">{anomaly.entry.url}</span>
                              </div>
                            )}
                            {anomaly.entry?.status_code && (
                              <div>
                                <span className="text-cyber-muted">Status: </span>
                                <span className={`font-mono ${
                                  anomaly.entry.status_code >= 400 ? 'text-red-400' : 'text-green-400'
                                }`}>
                                  {anomaly.entry.status_code}
                                </span>
                              </div>
                            )}
                            {anomaly.entry?.user && (
                              <div>
                                <span className="text-cyber-muted">User: </span>
                                <span className="font-mono text-cyber-text">{anomaly.entry.user}</span>
                              </div>
                            )}
                            {anomaly.entry?.action && (
                              <div>
                                <span className="text-cyber-muted">Action: </span>
                                <span className={`font-mono ${
                                  anomaly.entry.action === 'BLOCK' ? 'text-red-400' : 'text-green-400'
                                }`}>
                                  {anomaly.entry.action}
                                </span>
                              </div>
                            )}
                            {anomaly.entry?.category && (
                              <div>
                                <span className="text-cyber-muted">Category: </span>
                                <span className="font-mono text-cyber-text">{anomaly.entry.category}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {filtered.length === 0 && (
        <div className="px-5 py-10 text-center text-cyber-muted text-sm">
          No anomalies found{filter !== 'all' ? ` with severity "${filter}"` : ''}.
        </div>
      )}
    </div>
  );
}
