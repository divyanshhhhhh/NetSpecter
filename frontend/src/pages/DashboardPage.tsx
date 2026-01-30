import { motion } from 'framer-motion';
import { 
  Package, 
  Activity, 
  Clock, 
  AlertTriangle,
  Shield,
  Network,
  Server
} from 'lucide-react';
import { StatCard, StatGrid } from '../components/dashboard/StatCard';
import { ThreatList } from '../components/dashboard/ThreatList';
import { TrafficTimeline } from '../components/charts/TrafficTimeline';
import { ProtocolChart } from '../components/charts/ProtocolChart';
import { WiresharkFilters } from '../components/filters/WiresharkFilters';
import type { AnalysisResult } from '../types/analysis';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import { SeverityBadge } from '../components/ui/SeverityBadge';

interface DashboardPageProps {
  analysis: AnalysisResult;
}

export function DashboardPage({ analysis }: DashboardPageProps) {
  const { summary, statistics, detections, synthesis } = analysis;

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
    return `${(seconds / 3600).toFixed(1)}h`;
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const criticalThreats = detections.filter(d => d.severity === 'critical').length;
  const highThreats = detections.filter(d => d.severity === 'high').length;

  return (
    <div className="space-y-6 pb-8 px-4">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">
            Analysis Dashboard
          </h1>
          <p className="text-[hsl(var(--muted-foreground))] mt-1">
            {analysis.filename} • Analyzed {new Date(analysis.analysis_metadata.analysis_end).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {criticalThreats > 0 && (
            <SeverityBadge severity="critical" count={criticalThreats} />
          )}
          {highThreats > 0 && (
            <SeverityBadge severity="high" count={highThreats} />
          )}
          {criticalThreats === 0 && highThreats === 0 && detections.length === 0 && (
            <span className="flex items-center gap-2 px-3 py-1.5 bg-[hsl(var(--success))]/10 text-[hsl(var(--success))] rounded-full text-sm font-medium">
              <Shield size={16} />
              No threats detected
            </span>
          )}
        </div>
      </motion.div>

      {/* Executive Summary */}
      {synthesis.executive_summary && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card>
            <CardContent className="p-5">
              <p className="text-[hsl(var(--foreground))] leading-relaxed">
                {synthesis.executive_summary}
              </p>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Stats Grid */}
      <StatGrid columns={4}>
        <StatCard
          title="Total Packets"
          value={summary.total_packets}
          icon={Package}
          tooltip="Total number of packets captured in this file"
          delay={0.1}
        />
        <StatCard
          title="Traffic Volume"
          value={formatBytes(statistics.traffic_volume.total_bytes)}
          subtitle={`${summary.total_packets.toLocaleString()} packets`}
          icon={Activity}
          iconColor="text-emerald-400"
          tooltip="Total bytes transferred during capture"
          delay={0.15}
        />
        <StatCard
          title="Duration"
          value={formatDuration(summary.time_range.duration_seconds)}
          subtitle={`${new Date(summary.time_range.start).toLocaleTimeString()} - ${new Date(summary.time_range.end).toLocaleTimeString()}`}
          icon={Clock}
          iconColor="text-amber-400"
          tooltip="Time span of the packet capture"
          delay={0.2}
        />
        <StatCard
          title="Threat Indicators"
          value={summary.threat_indicators_found}
          icon={AlertTriangle}
          iconColor={summary.threat_indicators_found > 0 ? 'text-red-400' : 'text-gray-400'}
          tooltip="Number of potential security threats identified"
          delay={0.25}
        />
      </StatGrid>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
        >
          <TrafficTimeline
            data={statistics.temporal_analysis.packets_per_second}
            title="Packets per Second"
          />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.35 }}
        >
          <ProtocolChart
            data={summary.protocol_breakdown}
            title="Protocol Distribution"
          />
        </motion.div>
      </div>

      {/* Threats and Top Talkers */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <ThreatList detections={detections} maxItems={5} />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.45 }}
        >
          <TopTalkersCard topTalkers={statistics.top_talkers} />
        </motion.div>
      </div>

      {/* Wireshark Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <WiresharkFilters filters={synthesis.wireshark_filters} />
      </motion.div>

      {/* Recommendations */}
      {synthesis.recommendations.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.55 }}
        >
          <RecommendationsCard recommendations={synthesis.recommendations} />
        </motion.div>
      )}
    </div>
  );
}

interface TopTalkersCardProps {
  topTalkers: {
    by_bytes: { ip: string; bytes?: number }[];
    by_packets: { ip: string; packets?: number }[];
  };
}

function TopTalkersCard({ topTalkers }: TopTalkersCardProps) {
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={<Network size={20} />}>Top Talkers</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="divide-y divide-[hsl(var(--border))]">
          {topTalkers.by_bytes.slice(0, 5).map((talker, index) => (
            <motion.div
              key={talker.ip}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.05 }}
              className="px-5 py-3 flex items-center justify-between hover:bg-[hsl(var(--secondary))]/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <span className="w-6 h-6 flex items-center justify-center bg-[hsl(var(--secondary))] rounded-full text-xs font-medium text-[hsl(var(--muted-foreground))]">
                  {index + 1}
                </span>
                <div className="flex items-center gap-2">
                  <Server size={14} className="text-[hsl(var(--muted-foreground))]" />
                  <span className="font-mono text-sm text-[hsl(var(--foreground))]">
                    {talker.ip}
                  </span>
                </div>
              </div>
              <span className="text-sm text-[hsl(var(--muted-foreground))]">
                {talker.bytes ? formatBytes(talker.bytes) : 'N/A'}
              </span>
            </motion.div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

interface RecommendationsCardProps {
  recommendations: {
    id: string;
    priority: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    action_items: string[];
  }[];
}

function RecommendationsCard({ recommendations }: RecommendationsCardProps) {
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...recommendations].sort(
    (a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={<Shield size={20} />}>Recommendations</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="divide-y divide-[hsl(var(--border))]">
          {sorted.map((rec, index) => (
            <motion.div
              key={rec.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.05 }}
              className="p-5"
            >
              <div className="flex items-start gap-3">
                <SeverityBadge severity={rec.priority} size="sm" showIcon={false} />
                <div className="flex-1">
                  <h4 className="font-medium text-[hsl(var(--foreground))]">{rec.title}</h4>
                  <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))]">
                    {rec.description}
                  </p>
                  {rec.action_items.length > 0 && (
                    <ul className="mt-3 space-y-1">
                      {rec.action_items.map((item, i) => (
                        <li
                          key={i}
                          className="text-sm text-[hsl(var(--muted-foreground))] flex items-start gap-2"
                        >
                          <span className="text-[hsl(var(--primary))]">•</span>
                          {item}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
