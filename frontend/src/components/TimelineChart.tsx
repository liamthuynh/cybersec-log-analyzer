'use client';

import { TimelineBucket, Statistics } from '@/lib/api';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from 'recharts';

interface Props {
  timeline: TimelineBucket[];
  stats: Statistics;
}

export default function TimelineChart({ timeline, stats }: Props) {
  const chartData = timeline.map((t) => ({
    ...t,
    label: new Date(t.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Timeline Chart */}
      <div className="lg:col-span-2 bg-cyber-card rounded-xl border border-cyber-border p-5">
        <h3 className="text-sm font-semibold mb-4 text-cyber-text">Event Timeline</h3>
        {chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={chartData} barCategoryGap="20%">
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d3d" />
              <XAxis
                dataKey="label"
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={{ stroke: '#1e2d3d' }}
              />
              <YAxis
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={{ stroke: '#1e2d3d' }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a2332',
                  border: '1px solid #1e2d3d',
                  borderRadius: '8px',
                  fontSize: '12px',
                  color: '#e2e8f0',
                }}
              />
              <Legend wrapperStyle={{ fontSize: '11px', color: '#64748b' }} />
              <Bar dataKey="total" fill="#0891b2" name="Total Requests" radius={[3, 3, 0, 0]} />
              <Bar dataKey="errors" fill="#f59e0b" name="Errors" radius={[3, 3, 0, 0]} />
              <Bar dataKey="blocked" fill="#ef4444" name="Blocked" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-[280px] flex items-center justify-center text-cyber-muted text-sm">
            No timeline data available
          </div>
        )}
      </div>

      {/* Side panels */}
      <div className="space-y-4">
        {/* Top Domains */}
        <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
          <h3 className="text-sm font-semibold mb-3 text-cyber-text">Top Domains</h3>
          <div className="space-y-2">
            {stats.top_domains.slice(0, 6).map((d, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="text-cyber-muted font-mono truncate max-w-[160px]" title={d.domain}>
                  {d.domain}
                </span>
                <span className="text-cyber-text font-mono ml-2">{d.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top IPs */}
        <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
          <h3 className="text-sm font-semibold mb-3 text-cyber-text">Top Source IPs</h3>
          <div className="space-y-2">
            {stats.top_ips.slice(0, 6).map((d, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="text-cyber-muted font-mono">{d.ip}</span>
                <span className="text-cyber-text font-mono ml-2">{d.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Actions Breakdown */}
        <div className="bg-cyber-card rounded-xl border border-cyber-border p-5">
          <h3 className="text-sm font-semibold mb-3 text-cyber-text">Actions</h3>
          <div className="space-y-2">
            {Object.entries(stats.actions).map(([action, count]) => (
              <div key={action} className="flex items-center justify-between text-xs">
                <span className={`font-mono ${
                  action === 'BLOCK' ? 'text-red-400' :
                  action === 'ALLOW' ? 'text-green-400' : 'text-yellow-400'
                }`}>
                  {action}
                </span>
                <span className="text-cyber-text font-mono">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
