import { motion } from 'framer-motion';
import { 
  Loader2, 
  CheckCircle, 
  AlertCircle,
  FileSearch,
  BarChart3,
  Shield,
  Brain,
  Filter
} from 'lucide-react';
import { Card, CardContent } from '../components/ui/Card';
import { Progress } from '../components/ui/Progress';

interface AnalysisPhase {
  id: string;
  name: string;
  icon: typeof FileSearch;
  status: 'pending' | 'running' | 'complete' | 'error';
  description: string;
}

interface LiveAnalysisProps {
  currentPhase: string;
  progress: number;
  status: 'pending' | 'running' | 'complete' | 'error';
  filename: string;
  details?: {
    packetsProcessed?: number;
    detectionsFound?: number;
    currentActivity?: string;
  };
}

const phases: AnalysisPhase[] = [
  { id: 'parsing', name: 'Parsing PCAP', icon: FileSearch, status: 'pending', description: 'Reading packet data' },
  { id: 'statistics', name: 'Calculating Statistics', icon: BarChart3, status: 'pending', description: 'Traffic analysis' },
  { id: 'detection', name: 'Threat Detection', icon: Shield, status: 'pending', description: 'Scanning for threats' },
  { id: 'enrichment', name: 'Intelligence Enrichment', icon: Brain, status: 'pending', description: 'Gathering threat intel' },
  { id: 'synthesis', name: 'Generating Filters', icon: Filter, status: 'pending', description: 'Creating Wireshark filters' },
];

export function LiveAnalysis({ currentPhase, progress, status, filename, details }: LiveAnalysisProps) {
  const getPhaseStatus = (phaseId: string): 'pending' | 'running' | 'complete' | 'error' => {
    const phaseIndex = phases.findIndex(p => p.id === phaseId);
    const currentIndex = phases.findIndex(p => p.id === currentPhase);
    
    if (status === 'error' && phaseId === currentPhase) return 'error';
    if (phaseIndex < currentIndex) return 'complete';
    if (phaseIndex === currentIndex) return 'running';
    return 'pending';
  };

  return (
    <div className="max-w-3xl mx-auto py-10 px-6 space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center p-4"
      >
        <motion.div
          animate={{ rotate: status === 'running' ? 360 : 0 }}
          transition={{ duration: 2, repeat: status === 'running' ? Infinity : 0, ease: 'linear' }}
          className="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-[hsl(var(--primary))] to-blue-600 rounded-2xl flex items-center justify-center shadow-lg shadow-blue-500/20"
        >
          {status === 'complete' ? (
            <CheckCircle className="w-8 h-8 text-white" />
          ) : status === 'error' ? (
            <AlertCircle className="w-8 h-8 text-white" />
          ) : (
            <Loader2 className="w-8 h-8 text-white animate-spin" />
          )}
        </motion.div>
        <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">
          {status === 'complete' ? 'Analysis Complete' : status === 'error' ? 'Analysis Failed' : 'Analyzing...'}
        </h1>
        <p className="mt-2 text-[hsl(var(--muted-foreground))] font-mono text-sm">
          {filename}
        </p>
      </motion.div>

      {/* Progress */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="p-4 bg-[hsl(var(--card))] rounded-xl border border-[hsl(var(--border))]"
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-[hsl(var(--muted-foreground))]">Overall Progress</span>
          <span className="text-sm font-medium text-[hsl(var(--foreground))]">{Math.round(progress * 100)}%</span>
        </div>
        <Progress 
          value={progress * 100} 
          size="lg"
          variant={status === 'error' ? 'danger' : status === 'complete' ? 'success' : 'default'}
        />
      </motion.div>

      {/* Live stats */}
      {details && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="grid grid-cols-2 gap-6"
        >
          {details.packetsProcessed !== undefined && (
            <Card>
              <CardContent className="p-6 text-center">
                <p className="text-2xl font-bold text-[hsl(var(--foreground))]">
                  {details.packetsProcessed.toLocaleString()}
                </p>
                <p className="text-sm text-[hsl(var(--muted-foreground))]">Packets Processed</p>
              </CardContent>
            </Card>
          )}
          {details.detectionsFound !== undefined && (
            <Card>
              <CardContent className="p-6 text-center">
                <p className={`text-2xl font-bold ${details.detectionsFound > 0 ? 'text-[hsl(var(--warning))]' : 'text-[hsl(var(--success))]'}`}>
                  {details.detectionsFound}
                </p>
                <p className="text-sm text-[hsl(var(--muted-foreground))]">Detections Found</p>
              </CardContent>
            </Card>
          )}
        </motion.div>
      )}

      {/* Phase timeline */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card>
          <CardContent className="p-8">
            <div className="space-y-6">
              {phases.map((phase, index) => {
                const phaseStatus = getPhaseStatus(phase.id);
                const Icon = phase.icon;
                
                return (
                  <motion.div
                    key={phase.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.3 + index * 0.1 }}
                    className="flex items-center gap-4"
                  >
                    {/* Status indicator */}
                    <div className={`
                      relative w-10 h-10 rounded-full flex items-center justify-center
                      ${phaseStatus === 'complete' ? 'bg-[hsl(var(--success))]/20 text-[hsl(var(--success))]' :
                        phaseStatus === 'running' ? 'bg-[hsl(var(--primary))]/20 text-[hsl(var(--primary))]' :
                        phaseStatus === 'error' ? 'bg-[hsl(var(--destructive))]/20 text-[hsl(var(--destructive))]' :
                        'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))]'
                      }
                    `}>
                      {phaseStatus === 'running' ? (
                        <Loader2 size={20} className="animate-spin" />
                      ) : phaseStatus === 'complete' ? (
                        <CheckCircle size={20} />
                      ) : phaseStatus === 'error' ? (
                        <AlertCircle size={20} />
                      ) : (
                        <Icon size={20} />
                      )}
                    </div>

                    {/* Connector line */}
                    {index < phases.length - 1 && (
                      <div className={`
                        absolute left-[39px] top-[60px] w-0.5 h-8
                        ${phaseStatus === 'complete' ? 'bg-[hsl(var(--success))]' : 'bg-[hsl(var(--border))]'}
                      `} style={{ marginLeft: '-20px', marginTop: '20px' }} />
                    )}

                    {/* Phase info */}
                    <div className="flex-1">
                      <p className={`
                        font-medium
                        ${phaseStatus === 'running' ? 'text-[hsl(var(--primary))]' :
                          phaseStatus === 'complete' ? 'text-[hsl(var(--foreground))]' :
                          'text-[hsl(var(--muted-foreground))]'
                        }
                      `}>
                        {phase.name}
                      </p>
                      <p className="text-sm text-[hsl(var(--muted-foreground))]">
                        {phaseStatus === 'running' && details?.currentActivity 
                          ? details.currentActivity 
                          : phase.description}
                      </p>
                    </div>

                    {/* Status badge */}
                    <div className={`
                      px-2 py-1 rounded text-xs font-medium
                      ${phaseStatus === 'complete' ? 'bg-[hsl(var(--success))]/10 text-[hsl(var(--success))]' :
                        phaseStatus === 'running' ? 'bg-[hsl(var(--primary))]/10 text-[hsl(var(--primary))]' :
                        phaseStatus === 'error' ? 'bg-[hsl(var(--destructive))]/10 text-[hsl(var(--destructive))]' :
                        'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))]'
                      }
                    `}>
                      {phaseStatus === 'complete' ? 'Done' :
                       phaseStatus === 'running' ? 'Running' :
                       phaseStatus === 'error' ? 'Error' : 'Waiting'}
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
