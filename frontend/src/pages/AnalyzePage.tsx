import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileSearch,
  FolderOpen,
  Play,
  RefreshCw,
  FileText,
  Clock,
  HardDrive
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Tooltip } from '../components/ui/Tooltip';

// Use relative path to go through vite proxy
const API_BASE = '';

interface PcapFile {
  name: string;
  path: string;
  size: number;
  modified: string;
}

interface AnalyzePageProps {
  onStartAnalysis: (file: PcapFile) => void;
}

export function AnalyzePage({ onStartAnalysis }: AnalyzePageProps) {
  const [files, setFiles] = useState<PcapFile[]>([]);
  const [selectedFile, setSelectedFile] = useState<PcapFile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pcapFolder, setPcapFolder] = useState('/home/kali/SPR600/pcaps');

  const fetchFiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/api/pcaps`);
      if (response.ok) {
        const data = await response.json();
        setFiles(data.files || []);
        setPcapFolder(data.folder || pcapFolder);
      } else {
        throw new Error('Failed to load PCAP files');
      }
    } catch (err) {
      // Show helpful error message
      console.error('Failed to fetch PCAP files:', err);
      setError('Could not connect to backend. Make sure the backend server is running.');
      setFiles([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const handleStartAnalysis = () => {
    if (selectedFile) {
      onStartAnalysis(selectedFile);
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-12 px-6 space-y-16">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-6"
      >
        <div className="relative inline-block">
          <div className="absolute inset-0 bg-blue-500 blur-2xl opacity-20 rounded-full" />
          <div className="w-20 h-20 mx-auto bg-gradient-to-br from-[hsl(var(--primary))] to-blue-600 rounded-2xl flex items-center justify-center shadow-xl shadow-blue-500/30 relative z-10">
            <FileSearch className="w-10 h-10 text-white" />
          </div>
        </div>
        <div>
          <h1 className="text-4xl font-bold text-[hsl(var(--foreground))] tracking-tight">
            Analyze Packet Capture
          </h1>
          <p className="mt-3 text-lg text-[hsl(var(--muted-foreground))] max-w-2xl mx-auto">
            Select a PCAP file below to start detecting threats, generating filters, and inspecting traffic.
          </p>
        </div>
      </motion.div>

      {/* Folder path info */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <div className="bg-[hsl(var(--card))] rounded-2xl border border-[hsl(var(--border))] p-8 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/10 rounded-lg">
                <FolderOpen size={24} className="text-blue-500" />
              </div>
              <h3 className="text-lg font-semibold">Source Directory</h3>
            </div>
            <Tooltip content="Refresh file list">
              <Button
                variant="ghost"
                size="sm"
                onClick={fetchFiles}
                disabled={loading}
                className="hover:bg-blue-500/10 hover:text-blue-600"
              >
                <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
              </Button>
            </Tooltip>
          </div>
          <div className="bg-[hsl(var(--secondary))]/50 rounded-xl p-4 font-mono text-sm text-[hsl(var(--foreground))] border border-[hsl(var(--border))]/50">
            {pcapFolder}
          </div>
        </div>
      </motion.div>

      {/* File list */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <div className="space-y-6">
          <div className="flex items-center justify-between px-2">
            <h2 className="text-2xl font-bold tracking-tight">Available Files</h2>
            <span className="px-3 py-1 rounded-full bg-[hsl(var(--secondary))] text-sm font-medium text-[hsl(var(--muted-foreground))]">
              {files.length} PCAPs found
            </span>
          </div>

          <div className="space-y-4">
            {loading ? (
              <div className="p-12 text-center rounded-3xl border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--secondary))]/20">
                <RefreshCw className="w-10 h-10 mx-auto mb-4 animate-spin text-blue-500" />
                <p className="text-[hsl(var(--muted-foreground))] text-lg">Scanning directory...</p>
              </div>
            ) : error ? (
              <div className="p-12 text-center rounded-3xl border border-red-200 bg-red-50/50 dark:bg-red-900/10 dark:border-red-900/30">
                <p className="text-red-500 font-medium text-lg mb-4">{error}</p>
                <Button variant="secondary" onClick={fetchFiles}>
                  Retry Connection
                </Button>
              </div>
            ) : files.length === 0 ? (
              <div className="p-16 text-center rounded-3xl border-2 border-dashed border-[hsl(var(--border))]">
                <FolderOpen className="w-16 h-16 mx-auto mb-4 text-[hsl(var(--muted-foreground))]/50" />
                <p className="text-xl font-medium text-[hsl(var(--foreground))]">No PCAP files found</p>
                <p className="text-[hsl(var(--muted-foreground))] mt-2">
                  Add some .pcap files to the source directory to get started
                </p>
              </div>
            ) : (
              files.map((file, index) => (
                <motion.div
                  key={file.path}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  onClick={() => setSelectedFile(file)}
                  className={`
                    group relative p-6 cursor-pointer transition-all duration-300 rounded-2xl border-2
                    ${selectedFile?.path === file.path
                      ? 'bg-blue-50/50 dark:bg-blue-900/20 border-blue-500 shadow-lg shadow-blue-500/10'
                      : 'bg-[hsl(var(--card))] border-transparent hover:border-[hsl(var(--border))] hover:shadow-md'
                    }
                  `}
                >
                  <div className="flex items-start gap-6">
                    <div className={`
                      w-14 h-14 rounded-2xl flex items-center justify-center shrink-0 transition-colors duration-300
                      ${selectedFile?.path === file.path
                        ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/30'
                        : 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] group-hover:bg-blue-100 dark:group-hover:bg-blue-900/30 group-hover:text-blue-600 dark:group-hover:text-blue-400'
                      }
                    `}>
                      <FileText size={28} />
                    </div>

                    <div className="flex-1 min-w-0 pt-1">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className={`text-lg font-bold truncate transition-colors ${selectedFile?.path === file.path ? 'text-blue-600 dark:text-blue-400' : 'text-[hsl(var(--foreground))]'}`}>
                          {file.name}
                        </h3>
                        {selectedFile?.path === file.path && (
                          <motion.span
                            initial={{ scale: 0 }}
                            animate={{ scale: 1 }}
                            className="bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 text-xs px-3 py-1 rounded-full font-bold uppercase tracking-wide"
                          >
                            Selected
                          </motion.span>
                        )}
                      </div>

                      <div className="flex items-center gap-6 text-sm text-[hsl(var(--muted-foreground))]">
                        <span className="flex items-center gap-2">
                          <HardDrive size={16} />
                          {formatFileSize(file.size)}
                        </span>
                        <span className="flex items-center gap-2">
                          <Clock size={16} />
                          {formatDate(file.modified)}
                        </span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))
            )}
          </div>
        </div>
      </motion.div>

      {/* Action button - Isolated and Huge */}
      <AnimatePresence>
        {selectedFile && (
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 30 }}
            className="fixed bottom-10 left-1/2 -translate-x-1/2 z-50 pointer-events-none"
          >
            {/* This puts it fixed at bottom, but user asked for "in its own place". 
                 Let's stick to flow but with huge margin for better context. 
             */}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Re-doing the button to be inline but massive */}
      <AnimatePresence>
        {selectedFile && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="pt-12 text-center"
          >
            <Button
              size="lg"
              icon={Play}
              onClick={handleStartAnalysis}
              className="
                    h-16 px-12 text-xl rounded-full shadow-2xl shadow-blue-500/40 
                    bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500
                    border-0 ring-4 ring-blue-500/20 transition-all hover:scale-105 active:scale-95
                "
            >
              Start Analysis
            </Button>
            <p className="mt-6 text-[hsl(var(--muted-foreground))]">
              Ready to process <span className="text-blue-500 font-semibold">{selectedFile.name}</span>
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
