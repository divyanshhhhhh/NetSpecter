// Analysis result types matching backend response

export interface AnalysisResult {
  analysis_id: string;
  filename: string;
  summary: AnalysisSummary;
  statistics: Statistics;
  detections: Detection[];
  enrichment: EnrichmentResult;
  synthesis: Synthesis;
  analysis_metadata: AnalysisMetadata;
}

export interface AnalysisSummary {
  total_packets: number;
  time_range: TimeRange;
  protocol_breakdown: Record<string, number>;
  threat_indicators_found: number;
  severity_distribution: Record<string, number>;
}

export interface TimeRange {
  start: string;
  end: string;
  duration_seconds: number;
}

export interface Statistics {
  traffic_volume: TrafficVolume;
  protocol_analysis: ProtocolAnalysis;
  top_talkers: TopTalkers;
  temporal_analysis: TemporalAnalysis;
}

export interface TrafficVolume {
  total_bytes: number;
  total_packets: number;
  bytes_by_protocol: Record<string, number>;
  packets_by_protocol: Record<string, number>;
}

export interface ProtocolAnalysis {
  layer3: Record<string, number>;
  layer4: Record<string, number>;
  layer7: Record<string, number>;
}

export interface TopTalkers {
  by_bytes: Talker[];
  by_packets: Talker[];
  conversations: Conversation[];
}

export interface Talker {
  ip: string;
  bytes?: number;
  packets?: number;
}

export interface Conversation {
  src_ip: string;
  dst_ip: string;
  bytes: number;
  packets: number;
}

export interface TemporalAnalysis {
  packets_per_second: TimeSeriesPoint[];
  bytes_per_second: TimeSeriesPoint[];
  burst_detection: BurstDetection[];
}

export interface TimeSeriesPoint {
  timestamp: string;
  value: number;
}

export interface BurstDetection {
  start_time: string;
  end_time: string;
  peak_pps: number;
  average_pps: number;
}

export interface Detection {
  id: string;
  type: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  timestamp: string;
  source_ip?: string;
  destination_ip?: string;
  description: string;
  evidence: Record<string, unknown>;
  mitre_attack?: MitreAttack;
}

export interface MitreAttack {
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface EnrichmentResult {
  ip_reputation: Record<string, IpReputation>;
  domain_reputation: Record<string, DomainReputation>;
  geolocation: Record<string, GeoLocation>;
  asn_info: Record<string, AsnInfo>;
  threat_feeds: ThreatFeedMatch[];
}

export interface IpReputation {
  ip: string;
  reputation_score: number;
  categories: string[];
  last_seen?: string;
  source: string;
}

export interface DomainReputation {
  domain: string;
  reputation_score: number;
  categories: string[];
  registrar?: string;
  creation_date?: string;
  source: string;
}

export interface GeoLocation {
  ip: string;
  country: string;
  country_code: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
}

export interface AsnInfo {
  ip: string;
  asn: number;
  organization: string;
  country?: string;
}

export interface ThreatFeedMatch {
  indicator: string;
  indicator_type: string;
  feed_name: string;
  threat_type: string;
  confidence: number;
  last_seen?: string;
}

export interface Synthesis {
  executive_summary: string;
  threat_narrative: string;
  key_findings: KeyFinding[];
  risk_assessment: RiskAssessment;
  recommendations: Recommendation[];
  wireshark_filters: WiresharkFilter[];
  timeline_of_events: TimelineEvent[];
}

export interface KeyFinding {
  id: string;
  title: string;
  description: string;
  severity: string;
  affected_assets: string[];
  related_detections: string[];
}

export interface RiskAssessment {
  overall_risk_level: string;
  risk_score: number;
  risk_factors: RiskFactor[];
}

export interface RiskFactor {
  factor: string;
  impact: string;
  likelihood: string;
  description: string;
}

export interface Recommendation {
  id: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  action_items: string[];
}

export interface WiresharkFilter {
  id: string;
  name: string;
  description: string;
  filter: string;
  category: string;
  related_findings?: string[];
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  severity: string;
  related_detections?: string[];
}

export interface AnalysisMetadata {
  analysis_start: string;
  analysis_end: string;
  duration_seconds: number;
  pcap_size_bytes: number;
  analysis_version: string;
}

// Upload progress state
export interface UploadState {
  status: 'idle' | 'uploading' | 'analyzing' | 'complete' | 'error';
  progress: number;
  message?: string;
  error?: string;
}

// API response wrapper
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}
