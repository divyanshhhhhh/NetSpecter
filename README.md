# NetSpecter

**Network Packet Analysis Tool for Cybersecurity Investigation**

NetSpecter is a professional-grade network packet analysis tool designed for cybersecurity investigation. It automates deep packet inspection by combining statistical analysis, behavioral pattern detection, threat intelligence enrichment, and AI-powered anomaly identification.

## Features

- **Streaming PCAP Analysis**: Process PCAP files of any size (including 5GB+) without memory issues
- **Multi-Layer Detection**: Identify C2 beacons, DNS tunneling, data exfiltration, and port scanning
- **AI-Powered Insights**: Use LLMs via OpenRouter to interpret findings and provide actionable intelligence
- **Threat Intelligence Enrichment**: Correlate findings with VirusTotal, AbuseIPDB, and AlienVault OTX
- **Wireshark Integration**: Generate ready-to-use Wireshark filters for manual investigation

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend)

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

4. Run the backend server:
```bash
uvicorn backend.main:app --reload
```

5. (Optional) Set up the frontend:
```bash
cd frontend
npm install
npm run dev
```

### API Keys

| API | Purpose | Required | Free Tier |
|-----|---------|----------|-----------|
| OpenRouter | AI-powered analysis | Yes | Pay-per-use (free models available) |
| VirusTotal | IP/domain reputation | No | 500 req/day |
| AbuseIPDB | IP abuse reports | No | 1000 req/day |
| AlienVault OTX | Threat intel | No | 10000 req/day |

## Usage

### Web Interface

1. Navigate to `http://localhost:8000` in your browser
2. Upload a PCAP file or provide a filesystem path
3. Monitor analysis progress in real-time
4. Review findings and copy Wireshark filters

### API

```bash
# Upload and analyze a PCAP file
curl -X POST "http://localhost:8000/api/analyze" \
  -F "file=@capture.pcap"

# Analyze a PCAP file from filesystem path
curl -X POST "http://localhost:8000/api/analyze/path" \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/capture.pcap"}'

# Get analysis results
curl "http://localhost:8000/api/analysis/{analysis_id}"
```

## Architecture

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
