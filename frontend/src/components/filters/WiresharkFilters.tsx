import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Filter, 
  Copy, 
  Check, 
  ChevronDown,
  FileCode
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/Card';
import { Button } from '../ui/Button';
import { Tooltip } from '../ui/Tooltip';
import type { WiresharkFilter } from '../../types/analysis';
import { SeverityBadge } from '../ui/SeverityBadge';

interface WiresharkFiltersProps {
  filters: WiresharkFilter[];
}

export function WiresharkFilters({ filters }: WiresharkFiltersProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const groupedFilters = filters.reduce((acc, filter) => {
    const category = filter.category || 'General';
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(filter);
    return acc;
  }, {} as Record<string, WiresharkFilter[]>);

  const categoryOrder = ['Critical', 'Threats', 'Suspicious', 'Traffic Analysis', 'General'];
  const sortedCategories = Object.keys(groupedFilters).sort((a, b) => {
    const aIndex = categoryOrder.indexOf(a);
    const bIndex = categoryOrder.indexOf(b);
    if (aIndex === -1 && bIndex === -1) return a.localeCompare(b);
    if (aIndex === -1) return 1;
    if (bIndex === -1) return -1;
    return aIndex - bIndex;
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle icon={<Filter size={20} />}>
          Wireshark Filters
          <span className="ml-2 text-sm font-normal text-[hsl(var(--muted-foreground))]">
            ({filters.length} filters generated)
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {filters.length === 0 ? (
          <div className="p-8 text-center">
            <FileCode className="w-12 h-12 mx-auto mb-3 text-[hsl(var(--muted-foreground))]" />
            <p className="text-[hsl(var(--foreground))] font-medium">No filters generated</p>
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              Upload and analyze a PCAP file to generate Wireshark filters
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[hsl(var(--border))]">
            {sortedCategories.map((category) => (
              <div key={category}>
                <div className="px-5 py-3 bg-[hsl(var(--secondary))]/30">
                  <h4 className="text-sm font-medium text-[hsl(var(--foreground))] flex items-center gap-2">
                    {category}
                    <span className="text-xs text-[hsl(var(--muted-foreground))]">
                      ({groupedFilters[category].length})
                    </span>
                  </h4>
                </div>
                <div className="divide-y divide-[hsl(var(--border))]/50">
                  {groupedFilters[category].map((filter, index) => (
                    <FilterItem
                      key={filter.id}
                      filter={filter}
                      isExpanded={expandedId === filter.id}
                      onToggle={() => setExpandedId(expandedId === filter.id ? null : filter.id)}
                      index={index}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface FilterItemProps {
  filter: WiresharkFilter;
  isExpanded: boolean;
  onToggle: () => void;
  index: number;
}

function FilterItem({ filter, isExpanded, onToggle, index }: FilterItemProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(filter.filter);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityFromCategory = (category: string): 'critical' | 'high' | 'medium' | 'low' | 'info' => {
    if (category.toLowerCase().includes('critical')) return 'critical';
    if (category.toLowerCase().includes('threat')) return 'high';
    if (category.toLowerCase().includes('suspicious')) return 'medium';
    return 'info';
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.03 }}
      className="group"
    >
      <div
        onClick={onToggle}
        className="
          px-5 py-4
          flex items-start gap-4
          cursor-pointer
          hover:bg-[hsl(var(--secondary))]/30
          transition-colors
        "
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-[hsl(var(--foreground))]">
              {filter.name}
            </span>
            <SeverityBadge 
              severity={getSeverityFromCategory(filter.category)} 
              size="sm" 
              showIcon={false}
              showTooltip={false}
            />
          </div>
          <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))] line-clamp-1">
            {filter.description}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Tooltip content={copied ? 'Copied!' : 'Copy filter to clipboard'}>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleCopy}
              className="opacity-0 group-hover:opacity-100 transition-opacity"
            >
              {copied ? (
                <Check size={16} className="text-[hsl(var(--success))]" />
              ) : (
                <Copy size={16} />
              )}
            </Button>
          </Tooltip>
          <motion.div
            animate={{ rotate: isExpanded ? 180 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <ChevronDown size={18} className="text-[hsl(var(--muted-foreground))]" />
          </motion.div>
        </div>
      </div>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-4">
              <div className="relative">
                <pre className="
                  p-4
                  bg-[hsl(220,25%,5%)]
                  border border-[hsl(var(--border))]
                  rounded-lg
                  text-sm
                  font-mono
                  text-[hsl(var(--primary))]
                  overflow-x-auto
                  whitespace-pre-wrap
                  break-all
                ">
                  {filter.filter}
                </pre>
                <Tooltip content={copied ? 'Copied!' : 'Copy filter'}>
                  <button
                    onClick={handleCopy}
                    className="
                      absolute top-2 right-2
                      p-2
                      bg-[hsl(var(--secondary))]
                      border border-[hsl(var(--border))]
                      rounded-md
                      text-[hsl(var(--muted-foreground))]
                      hover:text-[hsl(var(--foreground))]
                      hover:bg-[hsl(var(--secondary))]/80
                      transition-colors
                    "
                  >
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                </Tooltip>
              </div>
              {filter.related_findings && filter.related_findings.length > 0 && (
                <div className="mt-3 text-xs text-[hsl(var(--muted-foreground))]">
                  <span className="font-medium">Related findings:</span>{' '}
                  {filter.related_findings.join(', ')}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
