import { motion } from 'framer-motion';
import type { LucideIcon } from 'lucide-react';
import { Tooltip } from '../ui/Tooltip';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  iconColor?: string;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  tooltip?: string;
  delay?: number;
}

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  iconColor = 'text-[hsl(var(--primary))]',
  trend,
  tooltip,
  delay = 0,
}: StatCardProps) {
  const card = (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.3, delay }}
      whileHover={{ y: -2, transition: { duration: 0.2 } }}
      className="
        bg-[hsl(var(--card))]
        border border-[hsl(var(--border))]
        rounded-xl
        p-5
        cursor-default
        transition-shadow duration-300
        hover:shadow-lg hover:shadow-black/10
      "
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-[hsl(var(--muted-foreground))] font-medium">
            {title}
          </p>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: delay + 0.1 }}
            className="mt-2 text-2xl font-bold text-[hsl(var(--foreground))]"
          >
            {typeof value === 'number' ? value.toLocaleString() : value}
          </motion.p>
          {subtitle && (
            <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
              {subtitle}
            </p>
          )}
          {trend && (
            <div className={`
              mt-2 flex items-center gap-1 text-xs font-medium
              ${trend.isPositive ? 'text-[hsl(var(--success))]' : 'text-[hsl(var(--destructive))]'}
            `}>
              <span>{trend.isPositive ? '↑' : '↓'}</span>
              <span>{Math.abs(trend.value)}%</span>
              <span className="text-[hsl(var(--muted-foreground))]">vs avg</span>
            </div>
          )}
        </div>
        <div className={`
          w-12 h-12 rounded-xl
          bg-[hsl(var(--secondary))]
          flex items-center justify-center
          ${iconColor}
        `}>
          <Icon size={24} />
        </div>
      </div>
    </motion.div>
  );

  if (tooltip) {
    return <Tooltip content={tooltip}>{card}</Tooltip>;
  }

  return card;
}

interface StatGridProps {
  children: React.ReactNode;
  columns?: 2 | 3 | 4;
}

export function StatGrid({ children, columns = 4 }: StatGridProps) {
  const gridCols = {
    2: 'grid-cols-1 sm:grid-cols-2',
    3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4',
  };

  return (
    <div className={`grid ${gridCols[columns]} gap-4`}>
      {children}
    </div>
  );
}
