# NetSpecter: Network Packet Analysis Tool

## Project Overview

NetSpecter is a professional-grade network packet analysis tool designed for cybersecurity investigation. It automates deep packet inspection by combining statistical analysis, behavioral pattern detection, threat intelligence enrichment, and AI-powered anomaly identification.

### Primary Goals

1. **Automate PCAP Analysis**: Process PCAP files of any size (including 5GB+) and extract security-relevant insights
2. **Multi-Layer Detection**: Identify C2 beacons, DNS tunneling, data exfiltration, and other malicious patterns
3. **AI-Powered Insights**: Use LLMs to interpret findings and provide actionable intelligence
4. **Threat Intelligence Enrichment**: Correlate findings with external reputation databases
5. **Actionable Output**: Generate Wireshark filters to enable manual deep-dive investigation

### What This Tool Does NOT Do

- No report generation (PDF/HTML exports)
- No Zeek/Suricata integration
- No database persistence (in-memory only)
- No production hardening (personal/local use)
- No real-time capture (PCAP file analysis only)

---

## Technology Stack

### Backend

| Component | Technology | Justification |
|-----------|------------|---------------|
| **Web Framework** | FastAPI | Async-native, WebSocket support, automatic OpenAPI docs |
| **PCAP Parsing** | dpkt + scapy | dpkt for fast streaming; scapy for deep protocol inspection |
| **Task Processing** | asyncio + BackgroundTasks | Simple async processing without external dependencies |
| **Storage** | In-memory (Python dicts) | No database overhead; temp files for large PCAPs |
| **Caching** | In-memory dict | 24hr TTL for threat intel results |

### AI Integration (OpenRouter)

| Phase | Model | Context | Purpose |
|-------|-------|---------|---------|
| **Statistical Analysis** | `meta-llama/llama-3.3-70b-instruct:free` | 131K tokens | Fast structured data interpretation |
| **Detection Analysis** | `deepseek/deepseek-r1-0528:free` | 164K tokens | Behavioral pattern reasoning |
| **Final Synthesis** | `tngtech/deepseek-r1t2-chimera:free` | 164K tokens | Correlate all findings, generate insights |

### Threat Intelligence APIs

| API | Purpose | Free Tier Limit |
|-----|---------|-----------------|
| **VirusTotal** | IP/domain/hash reputation | 500 requests/day, 4/min |
| **AbuseIPDB** | IP abuse reports | 1000 requests/day |
| **AlienVault OTX** | Threat intelligence pulses | 10000 requests/day |

### Frontend

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Framework** | React 18+ | Complex interactive visualizations |
| **Charts** | Recharts | Traffic timeline, protocol distribution |
| **Network Graphs** | Cytoscape.js | IP conversation topology |
| **Maps** | react-simple-maps | Geographic IP visualization |
| **Styling** | Tailwind CSS | Rapid UI development |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           React Frontend                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐│
│  │  Timeline   │ │  Network    │ │  Findings   │ │  Wireshark Filters  ││
│  │  Charts     │ │  Topology   │ │  Table      │ │  Export             ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                         WebSocket (progress) + REST API
                                    │
┌─────────────────────────────────────────────────────────────────────────┐
│                         FastAPI Backend                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                      Analysis Pipeline                               ││
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────────┐  ││
│  │  │  PCAP    │ → │ Stats    │ → │Detection │ → │ Threat Intel     │  ││
│  │  │  Parser  │   │ Engine   │   │ Engines  │   │ Enrichment       │  ││
│  │  └──────────┘   └──────────┘   └──────────┘   └──────────────────┘  ││
│  │       │              │              │                  │             ││
│  │       └──────────────┼──────────────┼──────────────────┘             ││
│  │                      ▼              ▼                                ││
│  │               ┌─────────────────────────────┐                        ││
│  │               │    OpenRouter LLM API       │                        ││
│  │               │  (3-phase AI integration)   │                        ││
│  │               └─────────────────────────────┘                        ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Upload**: User uploads PCAP file via web UI or provides filesystem path
2. **Parsing**: Streaming parser processes packets in chunks (10K packets/batch)
3. **Statistics**: Protocol distribution, conversations, timeline, entropy calculated
4. **LLM Phase 1**: Statistics sent to Llama 3.3 for initial anomaly flagging
5. **Detection**: Beacon, DNS tunnel, exfil, port scan detectors run on flows
6. **Filtering**: Only high-priority IPs/domains selected for threat intel queries
7. **Enrichment**: VirusTotal, AbuseIPDB, OTX queried for flagged indicators
8. **LLM Phase 2**: Detection results + threat intel sent to DeepSeek R1
9. **Synthesis**: All findings correlated by DeepSeek R1T2 Chimera
10. **Output**: Wireshark filters generated, results displayed in UI

---

## Large File Handling Strategy (5GB+ PCAPs)

### Streaming Architecture

```python
# Never load entire file - process packet by packet
for ts, buf in dpkt.pcap.Reader(file_handle):
    packet = parse_packet(ts, buf)
    update_incremental_stats(packet)
    
    if packet_count % 10000 == 0:
        yield_progress_update()
```

### Memory Management

| Threshold | Strategy |
|-----------|----------|
| < 1M packets | Keep all flow data in memory |
| 1M - 10M packets | Keep aggregated flows, discard raw packets |
| > 10M packets | Write intermediate results to temp JSON files |

### Efficient Data Structures

- `defaultdict` for flow aggregation
- `Counter` for protocol/IP counting
- Dataclasses with `__slots__` for packet summaries
- `heapq` for top-K tracking without storing all data

---

## Threat Intelligence Filtering Strategy

### The Problem

A 5GB PCAP may contain millions of unique IPs. Querying all of them would:
- Exhaust API rate limits instantly
- Take hours to complete
- Waste queries on benign traffic

### The Solution: Priority-Based Filtering

```
┌─────────────────────────────────────────────────────────────┐
│                    IP/Domain Filtering                       │
├─────────────────────────────────────────────────────────────┤
│  SKIP (Never Query)                                          │
│  ├── Private IPs (10.x, 172.16.x, 192.168.x)                │
│  ├── Loopback (127.x.x.x)                                   │
│  ├── Known CDNs (Cloudflare, AWS, Google, Akamai)           │
│  └── Broadcast/Multicast addresses                          │
├─────────────────────────────────────────────────────────────┤
│  HIGH PRIORITY (Query Immediately)                           │
│  ├── IPs flagged by detection engines                       │
│  │   ├── Beacon detection hits                              │
│  │   ├── DNS tunneling suspects                             │
│  │   └── Data exfiltration endpoints                        │
│  ├── Connections on suspicious ports (4444, 5555, 6666...)  │
│  ├── Failed connections (SYN without SYN-ACK)               │
│  └── Domains with suspicious TLDs (.tk, .xyz, .top, .pw)    │
├─────────────────────────────────────────────────────────────┤
│  MEDIUM PRIORITY (Query with Rate Limiting)                  │
│  ├── Top 100 external IPs by traffic volume                 │
│  ├── IPs with connections on non-standard ports             │
│  └── Rare destinations (< 5 connections total)              │
├─────────────────────────────────────────────────────────────┤
│  CACHE HIT (Use Cached Result)                               │
│  └── IPs queried within last 24 hours                       │
└─────────────────────────────────────────────────────────────┘
```

### Expected Query Reduction

| PCAP Size | Unique External IPs | After Filtering | Reduction |
|-----------|--------------------:|----------------:|----------:|
| 100 MB    | ~5,000              | ~50-100         | 98%       |
| 1 GB      | ~50,000             | ~100-200        | 99.6%     |
| 5 GB      | ~200,000            | ~200-500        | 99.8%     |

---

## API Key Configuration

### Environment Variables

```bash
# Required
OPENROUTER_API_KEY=sk-or-v1-xxxxx

# Optional (skip enrichment source if missing)
VIRUSTOTAL_API_KEY=xxxxx
ABUSEIPDB_API_KEY=xxxxx
OTX_API_KEY=xxxxx
```

### Graceful Degradation

```python
# If API key missing, log warning and skip that source
if not os.getenv('VIRUSTOTAL_API_KEY'):
    logger.warning("VIRUSTOTAL_API_KEY not set - VirusTotal enrichment disabled")
    skip_virustotal = True
```

---

## Project Structure

```
/home/kali/SPR600/
├── pyproject.toml                 # Dependencies and project metadata
├── README.md                      # Project documentation
├── .env.example                   # Example environment variables
├── .gitignore
│
├── backend/
│   ├── main.py                    # FastAPI app entry point
│   ├── config.py                  # Settings and environment loading
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py              # REST API endpoints
│   │   └── websocket.py           # WebSocket for progress updates
│   │
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── parser.py              # Streaming PCAP parser
│   │   ├── statistics.py          # Statistical analysis engine
│   │   ├── models.py              # Data models (Packet, Flow, Finding)
│   │   │
│   │   └── detectors/
│   │       ├── __init__.py
│   │       ├── base.py            # Base detector interface
│   │       ├── beacon.py          # C2 beacon detection
│   │       ├── dns_tunnel.py      # DNS tunneling detection
│   │       ├── exfiltration.py    # Data exfiltration patterns
│   │       └── port_scan.py       # Port scanning detection
│   │
│   ├── enrichment/
│   │   ├── __init__.py
│   │   ├── filter.py              # Priority-based IP filtering
│   │   ├── virustotal.py          # VirusTotal API client
│   │   ├── abuseipdb.py           # AbuseIPDB API client
│   │   ├── otx.py                 # AlienVault OTX client
│   │   └── cache.py               # In-memory result cache
│   │
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── openrouter.py          # OpenRouter API client
│   │   ├── prompts.py             # LLM prompt templates
│   │   └── context.py             # Context builder for LLM
│   │
│   └── output/
│       ├── __init__.py
│       └── wireshark.py           # Wireshark filter generator
│
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   │
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       │
│       ├── components/
│       │   ├── FileUpload.jsx
│       │   ├── ProgressBar.jsx
│       │   ├── TrafficTimeline.jsx
│       │   ├── ProtocolChart.jsx
│       │   ├── NetworkTopology.jsx
│       │   ├── FindingsTable.jsx
│       │   ├── WiresharkFilters.jsx
│       │   └── AIInsights.jsx
│       │
│       ├── hooks/
│       │   ├── useWebSocket.js
│       │   └── useAnalysis.js
│       │
│       └── api/
│           └── client.js
│
└── tests/
    ├── conftest.py
    ├── test_parser.py
    ├── test_detectors.py
    └── sample_pcaps/              # Test PCAP files
```

---

## Development Phases

---

### Phase 1: Project Setup & Streaming PCAP Parser

**Goal**: Create project foundation and implement a memory-efficient PCAP parser that can handle 5GB+ files.

**What We Build**:

1. **Project Scaffolding**
   - Initialize Python project with `pyproject.toml`
   - Set up FastAPI application skeleton
   - Create configuration module with environment variable loading
   - Set up logging infrastructure

2. **Streaming PCAP Parser** (`backend/analysis/parser.py`)
   - Implement packet-by-packet streaming using dpkt
   - Parse Ethernet, IP, TCP, UDP, ICMP layers
   - Extract DNS queries/responses
   - Extract HTTP requests/responses (basic)
   - Handle malformed packets gracefully
   - Progress callback for WebSocket updates

3. **Data Models** (`backend/analysis/models.py`)
   - `PacketSummary`: Lightweight packet representation with `__slots__`
   - `Flow`: Aggregated connection data (5-tuple key)
   - `Conversation`: IP pair with bidirectional stats
   - `DNSQuery`: DNS request/response pairs
   - `TLSInfo`: Certificate metadata

4. **Memory Management**
   - Chunk processing (10,000 packets per batch)
   - Incremental aggregation (don't store raw packets)
   - Configurable memory threshold for temp file fallback

**Key Files**:
- `backend/main.py`
- `backend/config.py`
- `backend/analysis/parser.py`
- `backend/analysis/models.py`

**Validation**:
- Parse 1GB test PCAP without memory spike
- Verify packet counts match Wireshark
- Measure processing speed (target: >100K packets/sec)

---

### Phase 2: Statistical Analysis Engine + LLM Insights

**Goal**: Extract comprehensive statistics from parsed data and use LLM to identify initial anomalies.

**What We Build**:

1. **Statistics Engine** (`backend/analysis/statistics.py`)
   - Protocol distribution (TCP/UDP/ICMP/DNS/HTTP/TLS breakdown)
   - Top talkers (source IPs, destination IPs, ports)
   - Conversation mapping with byte/packet counts
   - Timeline bucketing (traffic over time in 1-min intervals)
   - Session duration analysis
   - Payload entropy calculation (detect encrypted/encoded content)

2. **TLS Certificate Extraction**
   - Extract certificates from TLS handshakes
   - Parse subject, issuer, validity dates
   - Flag self-signed or expired certificates
   - Identify suspicious common names

3. **OpenRouter Integration** (`backend/ai/openrouter.py`)
   - API client with error handling
   - Model selection for each phase
   - Response parsing and validation

4. **LLM Context Builder** (`backend/ai/context.py`)
   - Format statistics as structured prompt
   - Include top anomalies, unusual patterns
   - Keep within context limits

5. **Phase 1 LLM Analysis** (Llama 3.3 70B)
   - Send statistical summary to LLM
   - Prompt for initial suspicions and anomalies
   - Parse LLM response into structured findings

**Key Files**:
- `backend/analysis/statistics.py`
- `backend/ai/openrouter.py`
- `backend/ai/prompts.py`
- `backend/ai/context.py`

**Example LLM Prompt (Phase 1)**:
```
You are a network security analyst. Analyze these PCAP statistics and identify potential security concerns.

## Traffic Overview
- Duration: 2 hours 15 minutes
- Total packets: 1,247,832
- Total bytes: 892 MB

## Protocol Distribution
- TCP: 78% (HTTP: 12%, HTTPS: 45%, Other: 21%)
- UDP: 18% (DNS: 15%, Other: 3%)
- ICMP: 4%

## Top External Destinations
1. 185.234.x.x (Russia) - 45,000 packets, 12 MB
2. 45.33.x.x (US) - 23,000 packets, 8 MB
...

## DNS Analysis
- Unique domains queried: 234
- Suspicious TLDs: 12 queries to .tk, 8 to .xyz

## Anomalies Detected
- 3 IP addresses with connection intervals of exactly 60 seconds
- High entropy payloads to external IP (possible encrypted C2)

Identify the top 5 security concerns and explain your reasoning.
```

**Validation**:
- Statistics match Wireshark's protocol hierarchy
- LLM returns parseable security insights
- Processing completes in reasonable time (<5 min for 1GB)

---

### Phase 3: Detection Engines

**Goal**: Implement specialized detectors for common attack patterns.

**What We Build**:

1. **Base Detector Interface** (`backend/analysis/detectors/base.py`)
   - Abstract base class for all detectors
   - Standard output format (Finding dataclass)
   - Confidence scoring methodology
   - Affected flows/packets tracking

2. **Beacon Detector** (`backend/analysis/detectors/beacon.py`)
   - Group connections by source-destination pair
   - Calculate inter-arrival time deltas
   - Compute jitter (standard deviation of intervals)
   - Score based on regularity (low jitter = high beacon score)
   - Detect common beacon intervals (30s, 60s, 300s, 900s)
   - Flag connections with >80% regularity score

3. **DNS Tunneling Detector** (`backend/analysis/detectors/dns_tunnel.py`)
   - Count unique subdomains per parent domain
   - Calculate entropy of subdomain strings
   - Detect unusual query types (TXT, NULL, CNAME chains)
   - Flag request/response size anomalies
   - Identify Base32/Base64 encoded subdomains

4. **Data Exfiltration Detector** (`backend/analysis/detectors/exfiltration.py`)
   - Calculate outbound/inbound byte ratio per destination
   - Flag large outbound transfers (>10MB to single external IP)
   - Detect off-hours bulk transfers
   - Identify uploads to paste sites, cloud storage
   - Flag unusual protocols for large transfers (DNS, ICMP)

5. **Port Scan Detector** (`backend/analysis/detectors/port_scan.py`)
   - Track connection attempts per source IP
   - Identify sequential port access patterns
   - Detect horizontal scans (one port, many hosts)
   - Detect vertical scans (one host, many ports)
   - Flag SYN-only connections (no SYN-ACK response)

**Finding Data Model**:
```python
@dataclass
class Finding:
    detector: str           # "beacon", "dns_tunnel", etc.
    severity: str           # "critical", "high", "medium", "low"
    confidence: float       # 0.0 - 1.0
    title: str              # Short description
    description: str        # Detailed explanation
    affected_ips: List[str]
    affected_flows: List[str]  # 5-tuple identifiers
    indicators: Dict        # Detector-specific data
    timestamp_range: Tuple[float, float]
```

**Key Files**:
- `backend/analysis/detectors/base.py`
- `backend/analysis/detectors/beacon.py`
- `backend/analysis/detectors/dns_tunnel.py`
- `backend/analysis/detectors/exfiltration.py`
- `backend/analysis/detectors/port_scan.py`

**Validation**:
- Test with known-malicious PCAPs (Malware Traffic Analysis samples)
- Verify beacon detection with synthetic regular-interval traffic
- Measure false positive rate on benign traffic

---

### Phase 4: Threat Intelligence Enrichment + LLM Analysis

**Goal**: Query external reputation APIs for flagged indicators and have LLM interpret results.

**What We Build**:

1. **IP/Domain Filter** (`backend/enrichment/filter.py`)
   - Classify IPs by priority (skip/high/medium/cache)
   - Filter out private, loopback, known-CDN ranges
   - Prioritize detector-flagged indicators
   - Limit queries to prevent rate limit exhaustion

2. **VirusTotal Client** (`backend/enrichment/virustotal.py`)
   - Query IP reputation endpoint
   - Query domain reputation endpoint
   - Parse detection counts and categories
   - Handle rate limiting (4 requests/min)

3. **AbuseIPDB Client** (`backend/enrichment/abuseipdb.py`)
   - Query IP check endpoint
   - Parse abuse confidence score
   - Extract report categories

4. **AlienVault OTX Client** (`backend/enrichment/otx.py`)
   - Query indicator endpoint
   - Parse pulse information
   - Extract threat tags and descriptions

5. **Result Cache** (`backend/enrichment/cache.py`)
   - In-memory dictionary with TTL
   - 24-hour expiration for benign results
   - 6-hour expiration for malicious results
   - Batch lookup support

6. **Phase 2 LLM Analysis** (DeepSeek R1)
   - Combine detection findings with threat intel
   - Send to DeepSeek R1 for behavioral interpretation
   - Request attack classification and TTPs

**Example LLM Prompt (Phase 2)**:
```
You are a threat intelligence analyst. Analyze these detection findings enriched with reputation data.

## Detection Findings

### Finding 1: C2 Beacon Detected (High Confidence: 92%)
- Source: 192.168.1.105 (internal workstation)
- Destination: 185.234.x.x:443
- Pattern: Connections every 60 seconds (±2s jitter)
- Duration: 2 hours continuous
- Threat Intel: VirusTotal - 12/90 detections (Cobalt Strike)

### Finding 2: DNS Tunneling Suspected (Medium Confidence: 68%)
- Domain: x7f3a.data.suspicious-domain.tk
- Pattern: 156 unique subdomains with high entropy (4.8 bits)
- Query Types: TXT records with Base64 responses
- Threat Intel: Domain registered 3 days ago

## Questions:
1. What type of attack does this represent?
2. What malware family is likely involved?
3. What MITRE ATT&CK techniques are being used?
4. What is the likely objective of the attacker?
5. What immediate actions should be taken?
```

**Key Files**:
- `backend/enrichment/filter.py`
- `backend/enrichment/virustotal.py`
- `backend/enrichment/abuseipdb.py`
- `backend/enrichment/otx.py`
- `backend/enrichment/cache.py`

**Validation**:
- Verify API calls are rate-limited correctly
- Test with known malicious indicators
- Confirm cache prevents duplicate queries

---

### Phase 5: Final Synthesis + Wireshark Filters

**Goal**: Correlate all findings and generate actionable Wireshark filters.

**What We Build**:

1. **Final LLM Synthesis** (DeepSeek R1T2 Chimera)
   - Aggregate all findings from previous phases
   - Correlate related events into attack chains
   - Generate executive summary
   - Provide confidence-scored conclusions
   - Recommend investigation priorities

2. **Wireshark Filter Generator** (`backend/output/wireshark.py`)
   - Generate display filters for each finding
   - Support IP, port, protocol, time range filters
   - Combine related filters with OR logic
   - Generate filters for conversation isolation
   - Create DNS query filters

**Filter Examples**:
```python
# Beacon traffic filter
"ip.addr == 185.234.x.x && tcp.port == 443"

# DNS tunneling filter
"dns.qry.name contains \"suspicious-domain.tk\""

# Time-bounded suspicious traffic
"(ip.src == 192.168.1.105) && (frame.time >= \"2024-01-15 10:30:00\" && frame.time <= \"2024-01-15 12:45:00\")"

# Port scan detection
"ip.src == 10.0.0.50 && tcp.flags.syn == 1 && tcp.flags.ack == 0"

# Large outbound transfers
"ip.src == 192.168.1.0/24 && ip.dst == 45.33.x.x && tcp.len > 1000"
```

3. **Output Models**
   - `AnalysisResult`: Complete analysis output
   - `WiresharkFilter`: Filter with description and finding reference
   - `AIInsight`: LLM-generated insight with confidence

**Key Files**:
- `backend/ai/prompts.py` (add synthesis prompt)
- `backend/output/wireshark.py`

**Validation**:
- Generated filters are valid Wireshark syntax
- Filters correctly isolate suspicious traffic
- Copy-paste filters work in Wireshark

---

### Phase 6: FastAPI Backend + React Frontend

**Goal**: Create web interface for file upload, real-time progress, and results visualization.

**What We Build**:

1. **FastAPI REST API** (`backend/api/routes.py`)
   - `POST /api/analyze` - Upload PCAP and start analysis
   - `POST /api/analyze/path` - Analyze PCAP from filesystem path
   - `GET /api/analysis/{id}` - Get analysis results
   - `GET /api/analysis/{id}/filters` - Get Wireshark filters
   - `GET /api/health` - Health check

2. **WebSocket Progress** (`backend/api/websocket.py`)
   - Real-time progress updates during analysis
   - Phase completion notifications
   - Error streaming

3. **React Application Setup**
   - Vite + React 18 + TypeScript
   - Tailwind CSS for styling
   - React Query for API state management

4. **Components**:

   **FileUpload.jsx**
   - Drag-and-drop PCAP upload
   - Filesystem path input option
   - File size display and validation

   **ProgressBar.jsx**
   - Multi-phase progress indicator
   - Current phase description
   - Packet count and elapsed time

   **TrafficTimeline.jsx** (Recharts)
   - Area chart of traffic over time
   - Inbound/outbound differentiation
   - Zoom and pan support
   - Highlight suspicious time ranges

   **ProtocolChart.jsx** (Recharts)
   - Pie chart of protocol distribution
   - Click to filter by protocol
   - Nested breakdown (TCP → HTTP/HTTPS/Other)

   **NetworkTopology.jsx** (Cytoscape.js)
   - Node-link diagram of IP conversations
   - Internal vs external IP color coding
   - Edge thickness by traffic volume
   - Highlight malicious connections in red
   - Click node for details

   **FindingsTable.jsx**
   - Sortable table of all findings
   - Severity color coding
   - Expand for full details
   - Filter by detector type

   **WiresharkFilters.jsx**
   - List of generated filters
   - One-click copy to clipboard
   - Grouped by finding
   - Export all as text file

   **AIInsights.jsx**
   - Display LLM-generated insights
   - Collapsible sections for each phase
   - Confidence indicators

**Key Files**:
- `backend/api/routes.py`
- `backend/api/websocket.py`
- `frontend/src/App.jsx`
- `frontend/src/components/*.jsx`

**Validation**:
- Upload 100MB PCAP through UI successfully
- Progress updates display in real-time
- All visualizations render correctly
- Wireshark filters copy to clipboard

---

## Detection Algorithm Details

### Beacon Detection Algorithm

```
For each unique (src_ip, dst_ip, dst_port) flow:
    1. Extract all connection timestamps
    2. Calculate inter-arrival deltas: Δt[i] = t[i+1] - t[i]
    3. Compute statistics:
       - mean(Δt): average interval
       - std(Δt): standard deviation (jitter)
       - count: number of connections
    4. Calculate beacon score:
       - regularity = 1 - (std(Δt) / mean(Δt))  # coefficient of variation inverse
       - if regularity > 0.8 and count > 10:
           FLAG as potential beacon
    5. Check common C2 intervals:
       - 30s, 60s, 120s, 300s, 600s, 900s, 3600s (±10%)
       - Increase confidence if matches known interval
```

### DNS Tunneling Detection Algorithm

```
For each parent domain (e.g., "evil.com"):
    1. Collect all subdomains queried
    2. Calculate metrics:
       - subdomain_count: unique subdomains
       - avg_length: average subdomain length
       - entropy: Shannon entropy of subdomain characters
       - query_types: distribution of A/AAAA/TXT/CNAME/NULL
    3. Scoring:
       - if subdomain_count > 50: +30 points
       - if avg_length > 30: +20 points
       - if entropy > 4.0: +25 points (high randomness)
       - if TXT queries > 20%: +15 points
       - if domain age < 30 days: +10 points
    4. If total score > 60: FLAG as potential tunnel
```

### Data Exfiltration Detection Algorithm

```
For each external destination IP:
    1. Calculate byte ratios:
       - outbound_bytes: total bytes sent TO this IP
       - inbound_bytes: total bytes received FROM this IP
       - ratio = outbound_bytes / max(inbound_bytes, 1)
    2. Scoring:
       - if ratio > 10 and outbound_bytes > 10MB: HIGH confidence
       - if ratio > 5 and outbound_bytes > 5MB: MEDIUM confidence
       - if ratio > 3 and outbound_bytes > 1MB: LOW confidence
    3. Additional flags:
       - Off-hours transfer (outside 9am-6pm): +20% confidence
       - Rare destination (first seen): +15% confidence
       - Non-standard port: +10% confidence
```

---

## Sample Wireshark Filters Output

```
# ============================================
# NetSpecter Analysis - Wireshark Filters
# Generated: 2026-01-29 14:32:15
# PCAP: suspicious_traffic.pcap
# ============================================

# Finding 1: C2 Beacon Activity (High Severity)
# Description: Regular 60-second beacon to known Cobalt Strike server
# Confidence: 92%
ip.addr == 185.234.72.15 && tcp.port == 443

# Finding 2: DNS Tunneling (Medium Severity)
# Description: High-entropy subdomains indicating data exfiltration via DNS
# Confidence: 78%
dns.qry.name contains "data.suspicious-domain.tk"

# Finding 3: Large Outbound Transfer (Medium Severity)
# Description: 45MB transferred to rare external IP
# Confidence: 65%
ip.src == 192.168.1.105 && ip.dst == 45.33.22.11

# Finding 4: Port Scan Detected (Low Severity)
# Description: Sequential port scan from internal host
# Confidence: 88%
ip.src == 10.0.0.50 && tcp.flags.syn == 1 && tcp.flags.ack == 0

# ============================================
# Combined Filter (All Suspicious Traffic)
# ============================================
(ip.addr == 185.234.72.15) || (dns.qry.name contains "suspicious-domain.tk") || (ip.dst == 45.33.22.11)
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- API Keys (optional but recommended):
  - OpenRouter API key (required for AI features)
  - VirusTotal API key
  - AbuseIPDB API key
  - AlienVault OTX API key

### Installation

```bash
# Clone and setup backend
cd /home/kali/SPR600
python -m venv venv
source venv/bin/activate
pip install -e .

# Setup frontend
cd frontend
npm install

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Running

```bash
# Terminal 1: Backend
cd /home/kali/SPR600
source venv/bin/activate
uvicorn backend.main:app --reload --port 8000

# Terminal 2: Frontend
cd /home/kali/SPR600/frontend
npm run dev
```

### Usage

1. Open http://localhost:5173 in browser
2. Upload a PCAP file or enter filesystem path
3. Watch real-time analysis progress
4. Review findings in interactive dashboard
5. Copy Wireshark filters for manual investigation

---

## Future Enhancements (Out of Scope)

- Real-time capture analysis (live traffic)
- PDF/HTML report export
- Zeek/Suricata integration
- Multi-user authentication
- Historical analysis comparison
- Custom detection rule editor
- STIX/TAXII IOC export
