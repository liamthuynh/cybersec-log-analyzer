'use client';

import { AISummary } from '@/lib/api';

interface Props {
  aiSummary: AISummary | null;
}

function ThreatBadge({ level }: { level: string }) {
  const config: Record<string, { bg: string; text: string }> = {
    critical: { bg: 'bg-red-500/20 border-red-500/40', text: 'text-red-400' },
    high: { bg: 'bg-orange-500/20 border-orange-500/40', text: 'text-orange-400' },
    medium: { bg: 'bg-yellow-500/20 border-yellow-500/40', text: 'text-yellow-400' },
    low: { bg: 'bg-green-500/20 border-green-500/40', text: 'text-green-400' },
  };
  const c = config[level] || config.low;

  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold border ${c.bg} ${c.text}`}>
      Threat Level: {level.toUpperCase()}
    </span>
  );
}

export default function AISummaryPanel({ aiSummary }: Props) {
  if (!aiSummary) {
    return (
      <div className="bg-cyber-card rounded-xl border border-cyber-border p-8 text-center">
        <p className="text-cyber-muted text-sm">AI analysis was not requested for this upload.</p>
      </div>
    );
  }

  // Handle the case where AI is not available — show fallback
  const summary = aiSummary.available === false
    ? aiSummary.fallback_summary || aiSummary
    : aiSummary;

  const isAIAvailable = aiSummary.available !== false;

  return (
    <div className="space-y-4">
      {/* AI availability notice */}
      {!isAIAvailable && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 text-sm">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-yellow-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <p className="text-yellow-300 font-medium">AI Analysis Unavailable</p>
              <p className="text-yellow-400/70 mt-1">
                {aiSummary.error || 'ANTHROPIC_API_KEY not set.'}
                {' '}{aiSummary.suggestion || 'Set the environment variable to enable AI-powered insights.'}
              </p>
              <p className="text-yellow-400/50 mt-2 text-xs">
                Showing rule-based fallback summary below.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Executive Summary */}
      <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            {isAIAvailable && (
              <span className="w-2 h-2 rounded-full bg-cyber-accent animate-pulse" />
            )}
            Executive Summary
          </h3>
          {summary.threat_level && <ThreatBadge level={summary.threat_level} />}
        </div>
        <p className="text-sm text-cyber-text/80 leading-relaxed">
          {summary.executive_summary || 'No summary available.'}
        </p>
      </div>

      {/* Key Findings */}
      {summary.key_findings && summary.key_findings.length > 0 && (
        <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
          <h3 className="text-sm font-semibold mb-4">Key Findings</h3>
          <div className="space-y-3">
            {summary.key_findings.map((finding: any, i: number) => (
              <div
                key={i}
                className="border border-cyber-border rounded-lg p-4 bg-cyber-bg/30"
              >
                <div className="flex items-start justify-between mb-2">
                  <h4 className="text-sm font-medium text-cyber-text">{finding.title}</h4>
                  {finding.severity && (
                    <span className={`badge badge-${finding.severity}`}>
                      {finding.severity}
                    </span>
                  )}
                </div>
                <p className="text-xs text-cyber-muted leading-relaxed">
                  {finding.description}
                </p>
                {finding.recommendation && (
                  <div className="mt-2 pt-2 border-t border-cyber-border/50">
                    <span className="text-xs text-cyber-accent">Recommendation: </span>
                    <span className="text-xs text-cyber-text/70">{finding.recommendation}</span>
                  </div>
                )}
                {finding.affected_entities && finding.affected_entities.length > 0 && (
                  <div className="mt-2 flex gap-1 flex-wrap">
                    {finding.affected_entities.map((e: string, j: number) => (
                      <span key={j} className="text-xs font-mono bg-cyber-bg px-2 py-0.5 rounded border border-cyber-border text-cyber-accent">
                        {e}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Timeline */}
      {summary.timeline && summary.timeline.length > 0 && (
        <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
          <h3 className="text-sm font-semibold mb-4">Event Timeline</h3>
          <div className="relative">
            <div className="absolute left-3 top-2 bottom-2 w-px bg-cyber-border" />
            <div className="space-y-4">
              {summary.timeline.map((event: any, i: number) => (
                <div key={i} className="pl-8 relative">
                  <div className="absolute left-1.5 top-1.5 w-3 h-3 rounded-full bg-cyber-accent/30 border-2 border-cyber-accent" />
                  <div className="text-xs font-mono text-cyber-accent mb-0.5">
                    {event.time}
                  </div>
                  <div className="text-sm text-cyber-text">{event.event}</div>
                  <div className="text-xs text-cyber-muted mt-0.5">{event.significance}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Patterns & Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {summary.patterns_detected && summary.patterns_detected.length > 0 && (
          <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
            <h3 className="text-sm font-semibold mb-3">Patterns Detected</h3>
            <div className="space-y-2">
              {summary.patterns_detected.map((pattern: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-xs text-cyber-text/80">
                  <span className="text-cyber-accent mt-0.5">▸</span>
                  {pattern}
                </div>
              ))}
            </div>
          </div>
        )}
        {summary.recommended_actions && summary.recommended_actions.length > 0 && (
          <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
            <h3 className="text-sm font-semibold mb-3">Recommended Actions</h3>
            <div className="space-y-2">
              {summary.recommended_actions.map((action: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-xs text-cyber-text/80">
                  <span className="text-green-400 font-mono mt-0.5">{i + 1}.</span>
                  {action}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
