import { 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  Info, 
  AlertCircle 
} from 'lucide-react';
import { motion } from 'framer-motion';
import { Tooltip } from './Tooltip';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  showTooltip?: boolean;
  count?: number;
}

const severityConfig: Record<Severity, {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
  icon: typeof AlertTriangle;
  description: string;
}> = {
  critical: {
    label: 'Critical',
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
    icon: ShieldAlert,
    description: 'Immediate action required. Active threat detected.',
  },
  high: {
    label: 'High',
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    icon: AlertTriangle,
    description: 'Significant threat requiring prompt attention.',
  },
  medium: {
    label: 'Medium',
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/30',
    icon: AlertCircle,
    description: 'Potential threat that should be investigated.',
  },
  low: {
    label: 'Low',
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    icon: Info,
    description: 'Minor issue or informational finding.',
  },
  info: {
    label: 'Info',
    color: 'text-gray-400',
    bgColor: 'bg-gray-500/10',
    borderColor: 'border-gray-500/30',
    icon: ShieldCheck,
    description: 'Informational finding, no action required.',
  },
};

export function SeverityBadge({
  severity,
  size = 'md',
  showIcon = true,
  showTooltip = true,
  count,
}: SeverityBadgeProps) {
  const config = severityConfig[severity];
  const Icon = config.icon;

  const sizes = {
    sm: 'px-2 py-0.5 text-xs gap-1',
    md: 'px-2.5 py-1 text-sm gap-1.5',
    lg: 'px-3 py-1.5 text-base gap-2',
  };

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  };

  const badge = (
    <motion.span
      whileHover={{ scale: 1.05 }}
      className={`
        inline-flex items-center ${sizes[size]}
        ${config.color} ${config.bgColor}
        border ${config.borderColor}
        rounded-full font-medium
        transition-all duration-200
      `}
    >
      {showIcon && <Icon size={iconSizes[size]} />}
      {config.label}
      {count !== undefined && (
        <span className="ml-1 px-1.5 py-0.5 bg-black/20 rounded-full text-xs">
          {count}
        </span>
      )}
    </motion.span>
  );

  if (showTooltip) {
    return <Tooltip content={config.description}>{badge}</Tooltip>;
  }

  return badge;
}

interface SeverityIndicatorProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
  pulse?: boolean;
}

export function SeverityIndicator({ severity, size = 'md', pulse = false }: SeverityIndicatorProps) {
  const config = severityConfig[severity];

  const sizes = {
    sm: 'w-2 h-2',
    md: 'w-3 h-3',
    lg: 'w-4 h-4',
  };

  const colorMap: Record<Severity, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
    info: 'bg-gray-500',
  };

  return (
    <Tooltip content={`${config.label}: ${config.description}`}>
      <span className="relative inline-flex">
        <span
          className={`
            ${sizes[size]} ${colorMap[severity]}
            rounded-full
            ${pulse && (severity === 'critical' || severity === 'high') ? 'animate-pulse' : ''}
          `}
        />
        {pulse && severity === 'critical' && (
          <span
            className={`
              absolute inset-0 ${sizes[size]} ${colorMap[severity]}
              rounded-full animate-ping opacity-75
            `}
          />
        )}
      </span>
    </Tooltip>
  );
}
