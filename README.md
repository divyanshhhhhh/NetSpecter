# NetSpecter

**Network Packet Analysis Tool for Cybersecurity Investigation**

*Author: Divyansh Pandya | License: MIT*

NetSpecter is a professional-grade network packet analysis tool designed for cybersecurity investigation. It automates deep packet inspection by combining statistical analysis, behavioral pattern detection, threat intelligence enrichment, and AI-powered anomaly identification.

## Objective

Automate the tedious, manual process of network forensics. Given a PCAP capture file, NetSpecter streams through the packets, computes traffic statistics, runs behavioral detectors for known attack patterns (C2 beacons, DNS tunneling, data exfiltration, port scanning), enriches findings against threat intelligence APIs, and uses an LLM to synthesize everything into actionable intelligence — complete with ready-to-use Wireshark filters for manual deep-dive.

## Features

- **Streaming PCAP Analysis**: Process PCAP files of any size (including 5GB+) without memory issues
- **Multi-Layer Detection**: Identify C2 beacons, DNS tunneling, data exfiltration, and port scanning
- **Smart Indicator Filtering**: Analyze top N% of traffic by volume to focus on high-value indicators
- **Cascading Threat Intelligence**: OTX → AbuseIPDB → VirusTotal enrichment with rate limiting
- **Typosquatting Detection**: Automatic detection of lookalike domains (e.g., g00gle.com, micr0soft.com)
- **AI-Powered Insights**: LLM-powered statistical interpretation and threat assessment via OpenRouter
- **Wireshark Integration**: Generate ready-to-use Wireshark display filters for manual investigation
- **Markdown Reports**: Save comprehensive analysis reports for documentation
- **Interactive CLI**: Rich command-line interface with colored output and progress indicators

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NetSpecter Analysis Pipeline                       │
│                                                                       │
│  Phase 1          Phase 2          Phase 3           Phase 4          │
│  ┌──────────┐   ┌──────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │  PCAP    │ → │ Stats    │ → │  Detection   │ → │   Smart      │  │
│  │  Parser  │   │ Engine   │   │  Engines     │   │   Filtering  │  │
│  │          │   │          │   │              │   │ + Enrichment │  │
│  │ Packets  │   │ Protos   │   │ C2 Beacon    │   │              │  │
│  │ Flows    │   │ Talkers  │   │ DNS Tunnel   │   │  OTX         │  │
│  │ DNS      │   │ Timeline │   │ Exfiltration │   │  AbuseIPDB   │  │
│  │ Convos   │   │ Anomaly  │   │ Port Scan    │   │  VirusTotal  │  │
│  └──────────┘   └──────────┘   └──────────────┘   └──────┬───────┘  │
│                                                           │          │
│                    Phase 5 + 6                 Phase 7     │          │
│                   ┌───────────────────┐   ┌──────────┐    │          │
│                   │  OpenRouter LLM   │ ← ┘  Wireshark│    │          │
│                   │                   │      Filter    │    │          │
│                   │  AI Analysis      │      Generator │    │          │
│                   │  + Synthesis      │   └──────────┘    │          │
│                   └───────────────────┘                    │          │
│                           │                                │          │
│                           ▼                                │          │
│                   Markdown Report                          │          │
└─────────────────────────────────────────────────────────────────────┘
```

### Analysis Phases

| Phase | Description | AI Model |
|-------|-------------|----------|
| **Phase 1: Parsing** | Stream-process PCAP file, extract packets, flows, and DNS queries | - |
| **Phase 2: Statistics** | Compute protocol distribution, top talkers, timeline analysis | - |
| **Phase 3: Detection** | Run C2 beacon, DNS tunnel, exfiltration, and port scan detectors | - |
| **Phase 4: Smart Filtering & Enrichment** | Filter top conversations, cascade through OTX → AbuseIPDB → VirusTotal | - |
| **Phase 5: AI Analysis** | LLM-powered statistical interpretation | `deepseek/deepseek-r1-0528:free` |
| **Phase 6: Synthesis** | Final correlation and threat assessment | `deepseek/deepseek-r1-0528:free` |
| **Phase 7: Filters** | Generate Wireshark display filters for flagged activity | - |

### Smart Indicator Filtering

NetSpecter minimizes API calls while maximizing detection coverage:

1. **Traffic Volume Analysis**: Ranks all conversations by byte count
2. **Configurable Selection**: Choose to analyze top or bottom N% of traffic
3. **Legitimate Domain Filtering**: Skips known-safe domains (configurable allowlist)
4. **Typosquatting Detection**: Flags lookalike domains (e.g., `g00gle.com`, `micr0soft.com`)
5. **Cascading Enrichment**:
   - OTX first (10,000/hour) — all selected indicators
   - AbuseIPDB second (1,000/day) — only OTX-flagged IPs
   - VirusTotal last (max 9/analysis) — highest priority threats only

## Getting Started

### Prerequisites

- Python 3.11+

### Installation

```bash
git clone https://github.com/divyanshhhhhh/NetSpecter.git
cd NetSpecter
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Configuration

Copy the environment file and add your API keys:

```bash
cp .env.example .env
```

```env
# Required for AI analysis
OPENROUTER_API_KEY=sk-or-v1-...

# Optional threat intelligence (recommended)
OTX_API_KEY=...
ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

| API | Purpose | Required | Limit |
|-----|---------|----------|-------|
| OpenRouter | AI-powered analysis (free models) | Yes | 50 req/day |
| AlienVault OTX | Threat intel pulses | No | 10,000 req/hour |
| AbuseIPDB | IP abuse reports | No | 1,000 req/day |
| VirusTotal | Deep malware scanning | No | 4 req/min (max 9/analysis) |

### Usage

```bash
# Analyze PCAPs in a directory
netspecter /path/to/pcaps

# Save results to JSON
netspecter /path/to/pcaps -o results.json

# Verbose mode
netspecter /path/to/pcaps -v
```

### Example Session

```
PHASE 4: Smart Indicator Filtering & Enrichment

Configure traffic filtering:
  [1] Top N% (highest traffic volume - typical for investigation)
  [2] Bottom N% (lowest traffic volume - look for hidden channels)
  [s] Skip enrichment entirely
Select [1/2/s] (default: 1): 1
Percentage to analyze (default: 40%): 25

Filtering Results:
  Total conversations: 847
  Analyzed (top 25%): 211 conversations

  Public IPs to check: 18
  Domains to check: 12
  Filtered by legitdomains.txt: 34

Proceed with enrichment? [Y/n] (n = re-configure): y
```

## Output

NetSpecter generates comprehensive markdown reports containing:

- **Traffic Overview**: Protocol distribution, packet counts, capture duration
- **Top Talkers**: Highest-volume source and destination IPs
- **Detection Results**: C2 beacon candidates, DNS tunnel indicators, exfiltration signals, port scan activity
- **Threat Intelligence**: OTX pulse matches, AbuseIPDB scores, VirusTotal detections
- **AI Analysis**: LLM-generated interpretation of statistical patterns and anomalies
- **Threat Assessment**: Final synthesized risk evaluation with confidence levels
- **Wireshark Filters**: Ready-to-paste display filters for each flagged indicator

## Detection Capabilities

| Detector | Description | Key Indicators |
|----------|-------------|----------------|
| **Beacon** | C2 callback detection | Regular intervals, low jitter |
| **DNS Tunnel** | DNS-based data exfiltration | High subdomain entropy, unusual query types |
| **Exfiltration** | Large outbound transfers | Asymmetric traffic ratios, off-hours transfers |
| **Port Scan** | Network reconnaissance | Sequential ports, SYN-only packets |

## Configuration

### Legitimate Domains List

Edit `backend/analysis/legitdomains.txt` to customize which domains are skipped during enrichment:

```
# Comments start with #
google.com
microsoft.com
amazon.com
# Add your organization's domains here
```

## Development

### Running Tests

```bash
pytest tests/ -v --cov=backend
```

### Code Quality

```bash
ruff check backend/
mypy backend/
```

## Tech Stack

- **PCAP Parsing**: dpkt + scapy (streaming, memory-efficient)
- **Detection Engines**: Custom Python analyzers for beacon, DNS tunnel, exfiltration, port scan patterns
- **Threat Intelligence**: AlienVault OTX, AbuseIPDB, VirusTotal (cascading with rate limits)
- **AI Analysis**: OpenRouter (DeepSeek R1, free tier)
- **CLI**: Rich (progress bars, tables, colored output)
- **Configuration**: Pydantic Settings + python-dotenv
- **API Server**: FastAPI + uvicorn (optional)

## License

MIT License - See [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Divyansh Pandya
