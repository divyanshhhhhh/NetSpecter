import axios, { type AxiosProgressEvent } from 'axios';
import type { AnalysisResult } from '../types/analysis';

const API_BASE = '/api';

export const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface AnalyzeOptions {
  onUploadProgress?: (progress: number) => void;
}

export async function analyzePcap(
  file: File,
  options?: AnalyzeOptions
): Promise<AnalysisResult> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await api.post<AnalysisResult>('/analyze', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (event: AxiosProgressEvent) => {
      if (event.total && options?.onUploadProgress) {
        const progress = Math.round((event.loaded * 100) / event.total);
        options.onUploadProgress(progress);
      }
    },
  });

  return response.data;
}

export async function getAnalysis(analysisId: string): Promise<AnalysisResult> {
  const response = await api.get<AnalysisResult>(`/analysis/${analysisId}`);
  return response.data;
}

export async function healthCheck(): Promise<{ status: string }> {
  const response = await api.get<{ status: string }>('/health');
  return response.data;
}
