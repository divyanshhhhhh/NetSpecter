# NetSpecter

**Network Packet Analysis Tool for Cybersecurity Investigation**

*Author: Divyansh Pandya | License: MIT*

NetSpecter is a professional-grade network packet analysis tool designed for cybersecurity investigation. It automates deep packet inspection by combining statistical analysis, behavioral pattern detection, threat intelligence enrichment, and AI-powered anomaly identification.

## Features

- **Streaming PCAP Analysis**: Process PCAP files of any size (including 5GB+) without memory issues
- **Multi-Layer Detection**: Identify C2 beacons, DNS tunneling, data exfiltration, and port scanning
- **AI-Powered Insights**: Use LLMs via OpenRouter to interpret findings and provide actionable intelligence
- **Threat Intelligence Enrichment**: Correlate findings with VirusTotal, AbuseIPDB, and AlienVault OTX
- **Wireshark Integration**: Generate ready-to-use Wireshark filters for manual investigation
- **Interactive CLI**: Beautiful command-line interface with colored output and progress bars

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

| API | Purpose | Required | Free Tier |
|-----|---------|----------|-----------|
| OpenRouter | AI-powered analysis | Yes | Pay-per-use (free models available) |
| VirusTotal | IP/domain reputation | No | 500 req/day |
| AbuseIPDB | IP abuse reports | No | 1000 req/day |
| AlienVault OTX | Threat intel | No | 10000 req/day |

## Usage

### Command Line Interface

Run NetSpecter with a directory containing PCAP files:

```bash
# Use default directory (~/SPR600/pcaps)
netspecter

# Specify a custom directory
netspecter /path/to/pcaps

# Save results to JSON file
netspecter /path/to/pcaps -o results.json
```

NetSpecter will:
1. Display a banner with tool description
2. Scan the directory for PCAP files
3. Show a list of available files
4. Prompt you to select a file to analyze
5. Run the multi-phase analysis with detailed output

### Analysis Phases

| Phase | Description |
|-------|-------------|
| **Phase 1: Parsing** | Stream-process PCAP file, extract packets and flows |
| **Phase 2: Statistics** | Compute protocol distribution, top talkers, timeline |
| **Phase 3: Detection** | Run beacon, DNS tunnel, exfiltration, port scan detectors |
| **Phase 4: Enrichment** | Query VirusTotal, AbuseIPDB, AlienVault OTX |
| **Phase 5: AI Analysis** | LLM-powered statistical interpretation |
| **Phase 6: Synthesis** | Final correlation and threat assessment |
| **Phase 7: Filters** | Generate Wireshark display filters |

### Example Output

```
 ███╗   ██╗███████╗████████╗███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ 
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║   ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

📁 Scanning directory: /home/user/pcaps

Found 3 PCAP files:
┌───┬────────────────────────────┬───────────┬──────────────────────┐
│ # │ Filename                   │ Size      │ Modified             │
├───┼────────────────────────────┼───────────┼──────────────────────┤
│ 1 │ suspicious_traffic.pcap    │ 156.2 MB  │ 2026-01-29 14:32     │
│ 2 │ network_capture.pcapng     │ 45.8 MB   │ 2026-01-28 09:15     │
│ 3 │ malware_sample.cap         │ 12.3 MB   │ 2026-01-27 16:45     │
└───┴────────────────────────────┴───────────┴──────────────────────┘

Select a file to analyze (1-3) or 'q' to quit: 1
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    NetSpecter CLI Application                           │
│                                                                         │
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
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                    Rich Console Output                               ││
│  │  • Progress bars  • Colored tables  • Phase indicators              ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

## Detection Capabilities

| Detector | Description | Key Indicators |
|----------|-------------|----------------|
| **Beacon** | C2 callback detection | Regular intervals, low jitter |
| **DNS Tunnel** | DNS-based data exfiltration | High subdomain entropy, unusual query types |
| **Exfiltration** | Large outbound transfers | Asymmetric traffic ratios, off-hours transfers |
| **Port Scan** | Network reconnaissance | Sequential ports, SYN-only packets |

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
