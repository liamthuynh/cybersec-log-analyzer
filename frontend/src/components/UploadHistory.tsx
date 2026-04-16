'use client';

import { UploadSummary } from '@/lib/api';

interface Props {
  history: UploadSummary[];
  onSelect?: (id: string) => void;
  loadingId?: string | null;
}

export default function UploadHistory({ history, onSelect, loadingId }: Props) {
  return (
    <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
      <h3 className="text-sm font-semibold mb-3">Upload History</h3>
      {history.length === 0 ? (
        <p className="text-xs text-cyber-muted">No uploads yet. Upload a log file to get started.</p>
      ) : (
        <div className="space-y-2 max-h-[240px] overflow-y-auto">
          {history.map((item) => (
            <button
              key={item.id}
              onClick={() => onSelect?.(item.id)}
              disabled={loadingId === item.id}
              className="w-full text-left flex items-center justify-between p-2.5 rounded-lg bg-cyber-bg/50 border border-cyber-border/50 hover:border-cyber-accent/50 hover:bg-cyber-accent/5 transition-colors disabled:opacity-60 disabled:cursor-wait"
            >
              <div className="min-w-0">
                <div className="text-xs font-mono text-cyber-text truncate">
                  {item.filename}
                </div>
                <div className="text-[10px] text-cyber-muted mt-0.5">
                  {new Date(item.upload_time).toLocaleString()}
                </div>
              </div>
              <div className="flex items-center gap-2 ml-3 flex-shrink-0">
                {loadingId === item.id ? (
                  <span className="w-3 h-3 border border-cyber-accent border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <span className="text-[10px] text-cyber-muted">
                      {item.total_entries} entries
                    </span>
                    {item.anomaly_count > 0 && (
                      <span className="badge badge-medium text-[10px]">
                        {item.anomaly_count}
                      </span>
                    )}
                  </>
                )}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
