# NetSpecter

**Network Packet Analysis Tool for Cybersecurity Investigation**

*Author: Divyansh Pandya | License: MIT*

NetSpecter is a professional-grade network packet analysis tool designed for cybersecurity investigation. It automates deep packet inspection by combining statistical analysis, behavioral pattern detection, threat intelligence enrichment, and AI-powered anomaly identification.

## Features

- **Streaming PCAP Analysis**: Process PCAP files of any size (including 5GB+) without memory issues
- **Multi-Layer Detection**: Identify C2 beacons, DNS tunneling, data exfiltration, and port scanning
- **Smart Indicator Filtering**: Analyze top N% of traffic by volume to focus on high-value indicators
- **Cascading Threat Intelligence**: OTX → AbuseIPDB → VirusTotal enrichment with rate limiting
- **Typosquatting Detection**: Automatic detection of lookalike domains (e.g., g00gle.com, micr0soft.com)
- **AI-Powered Insights**: Use LLMs via OpenRouter to interpret findings and provide actionable intelligence
- **Wireshark Integration**: Generate ready-to-use Wireshark filters for manual investigation
- **Markdown Reports**: Save comprehensive analysis reports for documentation
- **Interactive CLI**: Beautiful command-line interface with colored output and progress indicators

## Quick Start

### Prerequisites

- Python 3.11+

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd SPR600
```

2. Create a virtual environment and install dependencies:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

3. Copy the environment file and configure your API keys:
```bash
cp .env.example .env
# Edit .env with your API keys
```

### API Keys

This project uses free models available on OpenRouter for AI analysis.

| API | Purpose | Required | Limit |
|-----|---------|----------|-------|
| OpenRouter | AI-powered analysis (free models) | Yes | 50 req/day |
| AlienVault OTX | Threat intel pulses | No | 10,000 req/hour |
| AbuseIPDB | IP abuse reports | No | 1,000 req/day |
| VirusTotal | Deep malware scanning | No | 4 req/min (max 9/analysis) |

## Usage

### Running NetSpecter

```bash
# Use default directory (~/SPR600/pcaps)
netspecter

# Specify a custom directory
netspecter /path/to/pcaps

# Save results to JSON file
netspecter -o results.json

# Verbose mode for debugging
netspecter -v
```

### Interactive Workflow

1. **File Selection**: Choose a PCAP file from the discovered files list
2. **Traffic Filtering**: Configure what percentage of traffic to analyze:
   - Choose direction: Top N% (high volume) or Bottom N% (hidden channels)
   - Set percentage (default 40%)
   - Review indicator counts and confirm before API calls
3. **Enrichment**: Watch cascading threat intelligence lookups with live progress
4. **AI Analysis**: Review AI-generated insights and threat assessment
5. **Report**: Optionally save a comprehensive markdown report

### Analysis Phases

| Phase | Description | AI Model |
|-------|-------------|----------|
| **Phase 1: Parsing** | Stream-process PCAP file, extract packets and flows | - |
| **Phase 2: Statistics** | Compute protocol distribution, top talkers, timeline | - |
| **Phase 3: Detection** | Run beacon, DNS tunnel, exfiltration, port scan detectors | - |
| **Phase 4: Smart Filtering & Enrichment** | Filter top conversations, query OTX → AbuseIPDB → VirusTotal | - |
| **Phase 5: AI Analysis** | LLM-powered statistical interpretation | `deepseek/deepseek-r1-0528:free` |
| **Phase 6: Synthesis** | Final correlation and threat assessment | `deepseek/deepseek-r1-0528:free` |
| **Phase 7: Filters** | Generate Wireshark display filters | - |

### Smart Indicator Filtering

NetSpecter uses intelligent filtering to minimize API calls while maximizing detection:

1. **Traffic Volume Analysis**: Ranks all conversations by byte count
2. **Configurable Selection**: Choose to analyze top or bottom N% of traffic
3. **Legitimate Domain Filtering**: Skips known-safe domains (Google, Microsoft, etc.)
4. **Typosquatting Detection**: Flags domains like `g00gle.com`, `micr0soft.com`
5. **Cascading Enrichment**: 
   - OTX first (10,000/hour) - all selected indicators
   - AbuseIPDB second (1,000/day) - only OTX-flagged IPs
   - VirusTotal last (max 9/analysis) - highest priority threats only

### Example Session

```
PHASE 4: Smart Indicator Filtering & Enrichment

Configure traffic filtering:
  [1] Top N% (highest traffic volume - typical for investigation)
  [2] Bottom N% (lowest traffic volume - look for hidden channels)
  [s] Skip enrichment entirely
Select [1/2/s] (default: 1): 1
Percentage to analyze (default: 40%): 25

📊 Filtering Results:
  Total conversations: 847
  Analyzed (top 25%): 211 conversations
  
  Public IPs to check: 18
  Domains to check: 12
  Filtered by legitdomains.txt: 34

Proceed with enrichment? [Y/n] (n = re-configure): y
```

## Configuration

### Environment Variables

Create a `.env` file with:

```bash
# Required for AI analysis
OPENROUTER_API_KEY=sk-or-v1-...

# Optional threat intelligence (recommended)
OTX_API_KEY=...
ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

### Legitimate Domains List

Edit `backend/analysis/legitdomains.txt` to customize which domains are skipped:

```
# Comments start with #
google.com
microsoft.com
amazon.com
# Add your organization's domains here
```

## Detection Capabilities

| Detector | Description | Key Indicators |
|----------|-------------|----------------|
| **Beacon** | C2 callback detection | Regular intervals, low jitter |
| **DNS Tunnel** | DNS-based data exfiltration | High subdomain entropy, unusual query types |
| **Exfiltration** | Large outbound transfers | Asymmetric traffic ratios, off-hours transfers |
| **Port Scan** | Network reconnaissance | Sequential ports, SYN-only packets |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    NetSpecter CLI Application                           │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                      Analysis Pipeline                               ││
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────────┐  ││
│  │  │  PCAP    │ → │ Stats    │ → │Detection │ → │ Smart Filtering  │  ││
│  │  │  Parser  │   │ Engine   │   │ Engines  │   │ + Enrichment     │  ││
│  │  └──────────┘   └──────────┘   └──────────┘   └──────────────────┘  ││
│  │       │              │              │                  │             ││
│  │       └──────────────┼──────────────┼──────────────────┘             ││
│  │                      ▼              ▼                                ││
│  │               ┌─────────────────────────────┐                        ││
│  │               │    OpenRouter LLM API       │                        ││
│  │               │  (AI Analysis + Synthesis)  │                        ││
│  │               └─────────────────────────────┘                        ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                    Rich Console Output                               ││
│  │  • Live progress  • Red flagged indicators  • Markdown reports      ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

## Development

### Running Tests

```bash
pytest tests/ -v --cov=backend
```

### Code Quality

```bash
# Linting
ruff check backend/

# Type checking
mypy backend/
```

## License

MIT License - See LICENSE file for details.

Copyright (c) 2026 Divyansh Pandya
