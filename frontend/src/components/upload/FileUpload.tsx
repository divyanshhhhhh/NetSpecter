import { useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Upload, 
  FileUp, 
  X, 
  CheckCircle, 
  AlertCircle,
  FileSearch,
  Loader2
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Progress } from '../ui/Progress';
import { Card, CardContent } from '../ui/Card';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  onAnalyze: () => void;
  uploadState: {
    status: 'idle' | 'uploading' | 'analyzing' | 'complete' | 'error';
    progress: number;
    message?: string;
    error?: string;
  };
  selectedFile: File | null;
  onClear: () => void;
}

export function FileUpload({ 
  onFileSelect, 
  onAnalyze, 
  uploadState, 
  selectedFile,
  onClear 
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) {
        onFileSelect(file);
      }
    }
  }, [onFileSelect]);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      onFileSelect(files[0]);
    }
  }, [onFileSelect]);

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const isProcessing = uploadState.status === 'uploading' || uploadState.status === 'analyzing';

  return (
    <div className="w-full max-w-2xl mx-auto">
      <Card>
        <CardContent className="p-8">
          <AnimatePresence mode="wait">
            {!selectedFile ? (
              <motion.div
                key="dropzone"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={`
                    relative
                    border-2 border-dashed rounded-xl
                    p-12
                    text-center
                    cursor-pointer
                    transition-all duration-300
                    ${isDragging 
                      ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary))]/5' 
                      : 'border-[hsl(var(--border))] hover:border-[hsl(var(--primary))]/50 hover:bg-[hsl(var(--secondary))]/50'
                    }
                  `}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pcap,.pcapng"
                    onChange={handleFileChange}
                    className="hidden"
                  />
                  
                  <motion.div
                    animate={{ 
                      scale: isDragging ? 1.1 : 1,
                      y: isDragging ? -5 : 0
                    }}
                    transition={{ duration: 0.2 }}
                    className="flex flex-col items-center gap-4"
                  >
                    <div className={`
                      w-16 h-16 rounded-2xl
                      flex items-center justify-center
                      ${isDragging 
                        ? 'bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))]' 
                        : 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))]'
                      }
                      transition-colors duration-300
                    `}>
                      <Upload size={28} />
                    </div>
                    
                    <div>
                      <p className="text-lg font-medium text-[hsl(var(--foreground))]">
                        {isDragging ? 'Drop your file here' : 'Drag & drop your PCAP file'}
                      </p>
                      <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))]">
                        or click to browse • Supports .pcap and .pcapng
                      </p>
                    </div>
                  </motion.div>
                </div>
              </motion.div>
            ) : (
              <motion.div
                key="file-selected"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-6"
              >
                {/* File info */}
                <div className="flex items-center gap-4 p-4 bg-[hsl(var(--secondary))] rounded-xl">
                  <div className="w-12 h-12 bg-[hsl(var(--primary))]/10 rounded-xl flex items-center justify-center">
                    <FileSearch className="w-6 h-6 text-[hsl(var(--primary))]" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-[hsl(var(--foreground))] truncate">
                      {selectedFile.name}
                    </p>
                    <p className="text-sm text-[hsl(var(--muted-foreground))]">
                      {formatFileSize(selectedFile.size)}
                    </p>
                  </div>
                  {uploadState.status === 'idle' && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={onClear}
                      tooltip="Remove file"
                    >
                      <X size={18} />
                    </Button>
                  )}
                </div>

                {/* Progress */}
                {isProcessing && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    className="space-y-3"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Loader2 className="w-4 h-4 animate-spin text-[hsl(var(--primary))]" />
                        <span className="text-sm text-[hsl(var(--muted-foreground))]">
                          {uploadState.status === 'uploading' ? 'Uploading...' : 'Analyzing packets...'}
                        </span>
                      </div>
                      <span className="text-sm font-medium text-[hsl(var(--foreground))]">
                        {uploadState.progress}%
                      </span>
                    </div>
                    <Progress 
                      value={uploadState.progress} 
                      size="md"
                      variant={uploadState.status === 'analyzing' ? 'success' : 'default'}
                    />
                    {uploadState.message && (
                      <p className="text-xs text-[hsl(var(--muted-foreground))]">
                        {uploadState.message}
                      </p>
                    )}
                  </motion.div>
                )}

                {/* Success state */}
                {uploadState.status === 'complete' && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="flex items-center gap-3 p-4 bg-[hsl(var(--success))]/10 border border-[hsl(var(--success))]/30 rounded-xl"
                  >
                    <CheckCircle className="w-5 h-5 text-[hsl(var(--success))]" />
                    <span className="text-sm text-[hsl(var(--success))]">
                      Analysis complete! View results in the dashboard.
                    </span>
                  </motion.div>
                )}

                {/* Error state */}
                {uploadState.status === 'error' && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="flex items-center gap-3 p-4 bg-[hsl(var(--destructive))]/10 border border-[hsl(var(--destructive))]/30 rounded-xl"
                  >
                    <AlertCircle className="w-5 h-5 text-[hsl(var(--destructive))]" />
                    <span className="text-sm text-[hsl(var(--destructive))]">
                      {uploadState.error || 'An error occurred during analysis'}
                    </span>
                  </motion.div>
                )}

                {/* Actions */}
                <div className="flex gap-3">
                  {uploadState.status === 'idle' && (
                    <>
                      <Button
                        variant="secondary"
                        onClick={onClear}
                        className="flex-1"
                      >
                        Cancel
                      </Button>
                      <Button
                        icon={FileUp}
                        onClick={onAnalyze}
                        className="flex-1"
                        tooltip="Start analyzing the PCAP file for threats and anomalies"
                      >
                        Analyze PCAP
                      </Button>
                    </>
                  )}
                  {uploadState.status === 'error' && (
                    <>
                      <Button
                        variant="secondary"
                        onClick={onClear}
                        className="flex-1"
                      >
                        Try Another File
                      </Button>
                      <Button
                        onClick={onAnalyze}
                        className="flex-1"
                      >
                        Retry
                      </Button>
                    </>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </CardContent>
      </Card>

      {/* Features list */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="mt-8 grid grid-cols-3 gap-4"
      >
        {[
          { icon: '🔍', title: 'Deep Inspection', desc: 'Protocol-level analysis' },
          { icon: '🛡️', title: 'Threat Detection', desc: 'AI-powered security' },
          { icon: '📊', title: 'Rich Reports', desc: 'Wireshark filters included' },
        ].map((feature, i) => (
          <motion.div
            key={feature.title}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 + i * 0.1 }}
            className="text-center p-4"
          >
            <div className="text-2xl mb-2">{feature.icon}</div>
            <h4 className="font-medium text-sm text-[hsl(var(--foreground))]">{feature.title}</h4>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">{feature.desc}</p>
          </motion.div>
        ))}
      </motion.div>
    </div>
  );
}
