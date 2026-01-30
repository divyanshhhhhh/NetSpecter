import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  hover?: boolean;
  delay?: number;
}

export function Card({ children, className = '', hover = false, delay = 0 }: CardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay }}
      whileHover={hover ? { scale: 1.02, y: -2 } : undefined}
      className={`
        bg-[hsl(var(--card))]
        border border-[hsl(var(--border))]
        rounded-xl
        shadow-lg shadow-black/10
        p-2
        ${hover ? 'cursor-pointer transition-shadow hover:shadow-xl hover:shadow-black/20' : ''}
        ${className}
      `}
    >
      {children}
    </motion.div>
  );
}

interface CardHeaderProps {
  children: ReactNode;
  className?: string;
}

export function CardHeader({ children, className = '' }: CardHeaderProps) {
  return (
    <div className={`px-6 py-5 border-b border-[hsl(var(--border))] ${className}`}>
      {children}
    </div>
  );
}

interface CardTitleProps {
  children: ReactNode;
  className?: string;
  icon?: ReactNode;
}

export function CardTitle({ children, className = '', icon }: CardTitleProps) {
  return (
    <h3 className={`flex items-center gap-2 text-lg font-semibold text-[hsl(var(--foreground))] ${className}`}>
      {icon && <span className="text-[hsl(var(--primary))]">{icon}</span>}
      {children}
    </h3>
  );
}

interface CardContentProps {
  children: ReactNode;
  className?: string;
}

export function CardContent({ children, className = '' }: CardContentProps) {
  return (
    <div className={`p-6 ${className}`}>
      {children}
    </div>
  );
}

interface CardFooterProps {
  children: ReactNode;
  className?: string;
}

export function CardFooter({ children, className = '' }: CardFooterProps) {
  return (
    <div className={`px-6 py-5 border-t border-[hsl(var(--border))] ${className}`}>
      {children}
    </div>
  );
}
