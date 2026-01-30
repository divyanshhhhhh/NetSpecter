import { Search } from 'lucide-react';
import { motion } from 'framer-motion';

interface HeaderProps {
  sidebarCollapsed: boolean;
}

export function Header({ sidebarCollapsed }: HeaderProps) {
  const sidebarWidth = sidebarCollapsed ? 72 : 240;

  return (
    <motion.header
      initial={false}
      animate={{ left: sidebarWidth, width: `calc(100% - ${sidebarWidth}px)` }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
      className="
        fixed top-0 right-0
        h-20
        bg-[hsl(var(--card))]/80
        backdrop-blur-md
        border-b border-[hsl(var(--border))]
        flex items-center justify-center
        px-4 py-4
        z-30
      "
    >
      {/* Search bar - centered */}
      <div className="w-full max-w-5xl mx-auto px-8">
        <div className="w-full max-w-2xl mx-auto">
          <div className="relative">
            <div className="absolute left-4 inset-y-0 flex items-center text-[hsl(var(--muted-foreground))]">
              <Search size={20} />
            </div>
            <input
              type="text"
              placeholder="Search detections, IPs, domains..."
              className="
                w-full
                h-11
                pl-14 pr-4
                leading-none
                bg-[hsl(var(--secondary))]
                border border-[hsl(var(--border))]
                rounded-xl
                text-sm text-[hsl(var(--foreground))]
                placeholder:text-[hsl(var(--muted-foreground))]
                focus:outline-none focus:ring-2 focus:ring-[hsl(var(--primary))] focus:border-transparent
                transition-all duration-200
              "
            />
          </div>
        </div>
      </div>
    </motion.header>
  );
}
