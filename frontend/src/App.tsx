import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Sidebar } from './components/layout/Sidebar.tsx';
import { Header } from './components/layout/Header.tsx';
import { AnalyzePage } from './pages/AnalyzePage.tsx';
import { LiveAnalysis } from './pages/LiveAnalysis.tsx';
import { DashboardPage } from './pages/DashboardPage.tsx';
import type { AnalysisResult } from './types/analysis';

// Use relative path to go through vite proxy
const API_BASE = '';

interface PcapFile {
  name: string;
  path: string;
  size: number;
  modified: string;
}

interface AnalysisState {
  status: 'pending' | 'running' | 'complete' | 'error';
  currentPhase: string;
  progress: number;
  details: {
    packetsProcessed: number;
    detectionsFound: number;
    currentActivity: string;
  };
}

function App() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [currentView, setCurrentView] = useState('analyze');
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [selectedFile, setSelectedFile] = useState<PcapFile | null>(null);
  const sidebarWidth = sidebarCollapsed ? 72 : 240;
  const [analysisState, setAnalysisState] = useState<AnalysisState>({
    status: 'pending',
    currentPhase: 'parsing',
    progress: 0,
    details: {
      packetsProcessed: 0,
      detectionsFound: 0,
      currentActivity: '',
    },
  });

  const handleStartAnalysis = useCallback(async (file: PcapFile) => {
    setSelectedFile(file);
    setCurrentView('analyzing');
    setAnalysisState({
      status: 'running',
      currentPhase: 'parsing',
      progress: 0.05,
      details: {
        packetsProcessed: 0,
        detectionsFound: 0,
        currentActivity: 'Starting analysis...',
      },
    });

    try {
      // Start analysis via path endpoint
      const startResponse = await fetch(`${API_BASE}/api/analyze/path`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: file.path }),
      });

      if (!startResponse.ok) {
        const errorText = await startResponse.text();
        throw new Error(`Failed to start analysis: ${errorText}`);
      }

      const { analysis_id } = await startResponse.json();

      // Poll for analysis status
      const pollInterval = 500; // ms
      const maxPolls = 600; // 5 minutes max
      let polls = 0;

      const phaseProgress: Record<string, { phase: string; progress: number }> = {
        'pending': { phase: 'parsing', progress: 0.05 },
        'parsing': { phase: 'parsing', progress: 0.15 },
        'analyzing': { phase: 'statistics', progress: 0.35 },
        'detecting': { phase: 'detection', progress: 0.55 },
        'enriching': { phase: 'enrichment', progress: 0.75 },
        'synthesizing': { phase: 'synthesis', progress: 0.90 },
        'complete': { phase: 'synthesis', progress: 1.0 },
      };

      while (polls < maxPolls) {
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        polls++;

        const statusResponse = await fetch(`${API_BASE}/api/analysis/${analysis_id}`);
        if (!statusResponse.ok) {
          throw new Error('Failed to get analysis status');
        }

        const status = await statusResponse.json();
        const phaseInfo = phaseProgress[status.status] || { phase: 'parsing', progress: 0.1 };

        setAnalysisState(prev => ({
          ...prev,
          currentPhase: phaseInfo.phase,
          progress: phaseInfo.progress,
          details: {
            ...prev.details,
            packetsProcessed: status.packets_processed || prev.details.packetsProcessed,
            currentActivity: status.phase || 'Processing...',
          },
        }));

        if (status.status === 'complete') {
          // Get full results
          const resultsResponse = await fetch(`${API_BASE}/api/analysis/${analysis_id}/results`);
          if (resultsResponse.ok) {
            const result = await resultsResponse.json();
            setAnalysisResult(result);
            setAnalysisState(prev => ({
              ...prev,
              status: 'complete',
              progress: 1,
              details: {
                ...prev.details,
                detectionsFound: result.detections?.length || 0,
                currentActivity: 'Analysis complete',
              },
            }));
          } else {
            // Results endpoint might not exist, try to use stored results
            setAnalysisState(prev => ({
              ...prev,
              status: 'complete',
              progress: 1,
              details: {
                ...prev.details,
                currentActivity: 'Analysis complete',
              },
            }));
          }

          // Switch to dashboard after completion
          setTimeout(() => {
            setCurrentView('dashboard');
          }, 2000);
          return;
        }

        if (status.status === 'error') {
          throw new Error(status.error || 'Analysis failed');
        }
      }

      throw new Error('Analysis timed out');
    } catch (error) {
      console.error('Analysis failed:', error);
      setAnalysisState(prev => ({
        ...prev,
        status: 'error',
        details: {
          ...prev.details,
          currentActivity: error instanceof Error ? error.message : 'Analysis failed',
        },
      }));
    }
  }, []);

  const handleViewChange = useCallback((view: string) => {
    setCurrentView(view);
  }, []);

  const renderContent = () => {
    switch (currentView) {
      case 'analyze':
        return (
          <AnalyzePage onStartAnalysis={handleStartAnalysis} />
        );
      case 'analyzing':
        return (
          <LiveAnalysis
            currentPhase={analysisState.currentPhase}
            progress={analysisState.progress}
            status={analysisState.status}
            filename={selectedFile?.name || ''}
            details={analysisState.details}
          />
        );
      case 'dashboard':
        if (analysisResult) {
          return <DashboardPage analysis={analysisResult} />;
        }
        return (
          <div className="flex items-center justify-center h-full min-h-[60vh]">
            <div className="text-center">
              <p className="text-[hsl(var(--muted-foreground))]">
                No analysis results yet. Select a PCAP file to analyze.
              </p>
            </div>
          </div>
        );
      case 'detections':
        if (analysisResult) {
          return <DashboardPage analysis={analysisResult} />;
        }
        return (
          <div className="flex items-center justify-center h-full min-h-[60vh]">
            <div className="text-center">
              <p className="text-[hsl(var(--muted-foreground))]">
                No detections available. Analyze a PCAP file first.
              </p>
            </div>
          </div>
        );
      default:
        return (
          <div className="flex items-center justify-center h-full min-h-[60vh]">
            <div className="text-center">
              <h2 className="text-xl font-semibold text-[hsl(var(--foreground))] mb-2">
                Page Not Found
              </h2>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="min-h-screen bg-[hsl(var(--background))]">
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        currentView={currentView}
        onViewChange={handleViewChange}
      />
      <Header sidebarCollapsed={sidebarCollapsed} />

      <motion.main
        initial={false}
        animate={{
          marginLeft: sidebarWidth
        }}
        transition={{ duration: 0.2, ease: 'easeOut' }}
        style={{ width: `calc(100% - ${sidebarWidth}px)` }}
        className="min-h-screen pt-40 pb-12 flex justify-center"
      >
        <div className="w-full max-w-6xl px-8">
          {renderContent()}
        </div>
      </motion.main>
    </div>
  );
}

export default App;
