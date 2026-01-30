import { motion } from 'framer-motion';
import {
  Shield,
  Activity,
  FileSearch,
  ChevronLeft,
  ChevronRight,
  AlertTriangle
} from 'lucide-react';
import { Tooltip } from '../ui/Tooltip';

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  currentView: string;
  onViewChange: (view: string) => void;
}

const menuItems = [
  { id: 'analyze', icon: FileSearch, label: 'Analyze PCAP', tooltip: 'Select and analyze a packet capture file' },
  { id: 'dashboard', icon: Activity, label: 'Dashboard', tooltip: 'View analysis results and statistics' },
  { id: 'threats', icon: AlertTriangle, label: 'Detections', tooltip: 'View detected threats and anomalies' },
];

export function Sidebar({ collapsed, onToggle, currentView, onViewChange }: SidebarProps) {
  return (
    <motion.aside
      initial={false}
      animate={{ width: collapsed ? 72 : 240 }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
      className="
        fixed left-0 top-0 bottom-0
        bg-[hsl(var(--card))]
        border-r border-[hsl(var(--border))]
        flex flex-col
        z-40
      "
    >
      {/* Logo */}
      <div className="h-24 flex items-center justify-center border-b border-[hsl(var(--border))]">
        <motion.div
          className="flex items-center gap-4"
          animate={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
        >
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl flex items-center justify-center shadow-lg shadow-blue-500/25 ring-2 ring-white/10">
            <Shield className="w-7 h-7 text-white" />
          </div>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              className="flex flex-col"
            >
              <span className="font-bold text-xl tracking-tight text-[hsl(var(--foreground))] whitespace-nowrap overflow-hidden">
                NetSpecter
              </span>
              <span className="text-xs text-[hsl(var(--muted-foreground))] uppercase tracking-wider font-semibold">
                Security Node
              </span>
            </motion.div>
          )}
        </motion.div>
      </div>

      {/* Main menu */}
      <nav className="flex-1 py-8 px-4 space-y-3">
        {menuItems.map((item) => (
          <NavItem
            key={item.id}
            icon={item.icon}
            label={item.label}
            tooltip={item.tooltip}
            collapsed={collapsed}
            active={currentView === item.id}
            onClick={() => onViewChange(item.id)}
          />
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={onToggle}
        className="
          absolute -right-4 top-24
          w-8 h-8
          bg-[hsl(var(--card))]
          border border-[hsl(var(--border))]
          rounded-full
          flex items-center justify-center
          text-[hsl(var(--muted-foreground))]
          hover:text-[hsl(var(--foreground))]
          hover:bg-[hsl(var(--secondary))]
          transition-all duration-200
          shadow-xl hover:shadow-2xl hover:scale-105
          z-50
        "
      >
        {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>
    </motion.aside>
  );
}

interface NavItemProps {
  icon: typeof Shield;
  label: string;
  tooltip: string;
  collapsed: boolean;
  active: boolean;
  onClick: () => void;
}

function NavItem({ icon: Icon, label, tooltip, collapsed, active, onClick }: NavItemProps) {
  const button = (
    <motion.button
      whileHover={{ scale: 1.01, x: 4 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className={`
        w-full flex items-center gap-4 px-5 py-4 rounded-2xl
        transition-all duration-300 relative overflow-hidden group
        ${active
          ? 'text-white shadow-lg shadow-blue-500/25'
          : 'text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(var(--secondary))]/50'
        }
        ${collapsed ? 'justify-center px-0' : ''}
      `}
    >
      {active && (
        <motion.div
          layoutId="activeTabBackground"
          className="absolute inset-0 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl -z-10"
          initial={false}
          transition={{ type: "spring", stiffness: 500, damping: 30 }}
        />
      )}

      <Icon size={22} className={`relative z-10 transition-colors duration-200 ${active ? 'text-white' : 'group-hover:text-blue-500'}`} />

      {!collapsed && (
        <motion.span
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="font-semibold text-lg whitespace-nowrap overflow-hidden relative z-10"
        >
          {label}
        </motion.span>
      )}
    </motion.button>
  );

  if (collapsed) {
    return <Tooltip content={tooltip} side="right">{button}</Tooltip>;
  }

  return button;
}
