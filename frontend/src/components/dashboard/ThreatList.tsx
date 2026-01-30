import { motion } from 'framer-motion';
import { AlertTriangle, Shield, Clock, ChevronRight } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/Card';
import { SeverityBadge, SeverityIndicator } from '../ui/SeverityBadge';
import type { Detection } from '../../types/analysis';

interface ThreatListProps {
  detections: Detection[];
  maxItems?: number;
  onViewAll?: () => void;
}

export function ThreatList({ detections, maxItems = 5, onViewAll }: ThreatListProps) {
  const sortedDetections = [...detections]
    .sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    })
    .slice(0, maxItems);

  const criticalCount = detections.filter(d => d.severity === 'critical').length;
  const highCount = detections.filter(d => d.severity === 'high').length;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle icon={<Shield size={20} />}>
          Detected Threats
          {(criticalCount > 0 || highCount > 0) && (
            <span className="ml-2 flex items-center gap-1">
              {criticalCount > 0 && (
                <span className="px-2 py-0.5 text-xs bg-red-500/10 text-red-400 rounded-full">
                  {criticalCount} critical
                </span>
              )}
              {highCount > 0 && (
                <span className="px-2 py-0.5 text-xs bg-orange-500/10 text-orange-400 rounded-full">
                  {highCount} high
                </span>
              )}
            </span>
          )}
        </CardTitle>
        {detections.length > maxItems && onViewAll && (
          <button
            onClick={onViewAll}
            className="flex items-center gap-1 text-sm text-[hsl(var(--primary))] hover:underline"
          >
            View all <ChevronRight size={16} />
          </button>
        )}
      </CardHeader>
      <CardContent className="p-0">
        {sortedDetections.length === 0 ? (
          <div className="p-8 text-center">
            <Shield className="w-12 h-12 mx-auto mb-3 text-[hsl(var(--success))]" />
            <p className="text-[hsl(var(--foreground))] font-medium">No threats detected</p>
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              The analysis found no security threats in this capture
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[hsl(var(--border))]">
            {sortedDetections.map((detection, index) => (
              <ThreatItem key={detection.id} detection={detection} index={index} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface ThreatItemProps {
  detection: Detection;
  index: number;
}

function ThreatItem({ detection, index }: ThreatItemProps) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className="
        p-4 
        hover:bg-[hsl(var(--secondary))]/50 
        transition-colors 
        cursor-pointer
        group
      "
    >
      <div className="flex items-start gap-4">
        <SeverityIndicator severity={detection.severity} pulse={detection.severity === 'critical'} />
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-[hsl(var(--foreground))] group-hover:text-[hsl(var(--primary))] transition-colors">
              {detection.type}
            </span>
            <SeverityBadge severity={detection.severity} size="sm" showIcon={false} />
            {detection.mitre_attack && (
              <span className="px-2 py-0.5 text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20 rounded">
                {detection.mitre_attack.technique_id}
              </span>
            )}
          </div>
          
          <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))] line-clamp-2">
            {detection.description}
          </p>
          
          <div className="mt-2 flex items-center gap-4 text-xs text-[hsl(var(--muted-foreground))]">
            {detection.source_ip && (
              <span className="flex items-center gap-1">
                <span className="text-[hsl(var(--foreground))]">{detection.source_ip}</span>
                {detection.destination_ip && (
                  <>
                    <span>→</span>
                    <span className="text-[hsl(var(--foreground))]">{detection.destination_ip}</span>
                  </>
                )}
              </span>
            )}
            <span className="flex items-center gap-1">
              <Clock size={12} />
              {new Date(detection.timestamp).toLocaleTimeString()}
            </span>
            <span className="flex items-center gap-1">
              <AlertTriangle size={12} />
              {Math.round(detection.confidence * 100)}% confidence
            </span>
          </div>
        </div>
        
        <ChevronRight 
          size={20} 
          className="text-[hsl(var(--muted-foreground))] opacity-0 group-hover:opacity-100 transition-opacity" 
        />
      </div>
    </motion.div>
  );
}
