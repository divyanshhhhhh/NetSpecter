"""
NetSpecter REST API Routes

Defines all REST API endpoints for PCAP analysis.
"""

import uuid
from pathlib import Path
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from backend.config import settings

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["analysis"])


# =============================================================================
# Request/Response Models
# =============================================================================


class AnalyzePathRequest(BaseModel):
    """Request to analyze a PCAP file from filesystem path."""

    path: str = Field(..., description="Filesystem path to the PCAP file")


class AnalysisResponse(BaseModel):
    """Response after initiating an analysis."""

    analysis_id: str = Field(..., description="Unique analysis identifier")
    status: str = Field(..., description="Current analysis status")
    message: str = Field(..., description="Status message")


class AnalysisStatus(BaseModel):
    """Current status of an analysis."""

    analysis_id: str
    status: str  # "pending", "parsing", "analyzing", "enriching", "complete", "error"
    phase: str  # Current phase description
    progress: float  # 0.0 - 1.0
    packets_processed: int
    total_packets: int | None
    elapsed_seconds: float
    error: str | None = None


# =============================================================================
# In-Memory Analysis Store
# =============================================================================

# Simple in-memory storage for analysis jobs
# In production, this would be replaced with a proper task queue
_analyses: dict[str, dict] = {}


# =============================================================================
# API Endpoints
# =============================================================================


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_upload(
    background_tasks: BackgroundTasks,
    file: Annotated[UploadFile, File(description="PCAP file to analyze")],
) -> AnalysisResponse:
    """
    Upload and analyze a PCAP file.

    Accepts PCAP/PCAPNG files up to the configured maximum size.
    Returns an analysis ID that can be used to check status and retrieve results.
    """
    # Validate file type
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    valid_extensions = {".pcap", ".pcapng", ".cap"}
    suffix = Path(file.filename).suffix.lower()
    if suffix not in valid_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Accepted: {', '.join(valid_extensions)}",
        )

    # Generate analysis ID
    analysis_id = str(uuid.uuid4())

    # Save uploaded file to temp directory
    temp_path = settings.ensure_temp_dir() / f"{analysis_id}{suffix}"

    try:
        # Stream file to disk to handle large files
        with open(temp_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):  # 1MB chunks
                f.write(chunk)
    except Exception as e:
        logger.error("file_upload_failed", analysis_id=analysis_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to save uploaded file")

    logger.info(
        "file_uploaded",
        analysis_id=analysis_id,
        filename=file.filename,
        size_bytes=temp_path.stat().st_size,
    )

    # Initialize analysis record
    _analyses[analysis_id] = {
        "id": analysis_id,
        "status": "pending",
        "phase": "Queued for processing",
        "progress": 0.0,
        "packets_processed": 0,
        "total_packets": None,
        "elapsed_seconds": 0.0,
        "file_path": str(temp_path),
        "original_filename": file.filename,
        "results": None,
        "error": None,
    }

    # Start background analysis task
    background_tasks.add_task(run_analysis, analysis_id, temp_path)

    return AnalysisResponse(
        analysis_id=analysis_id,
        status="pending",
        message=f"Analysis started for {file.filename}",
    )


@router.post("/analyze/path", response_model=AnalysisResponse)
async def analyze_path(
    background_tasks: BackgroundTasks,
    request: AnalyzePathRequest,
) -> AnalysisResponse:
    """
    Analyze a PCAP file from a filesystem path.

    Useful for analyzing large files without uploading.
    """
    file_path = Path(request.path)

    # Validate file exists
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {request.path}")

    if not file_path.is_file():
        raise HTTPException(status_code=400, detail="Path is not a file")

    # Validate extension
    valid_extensions = {".pcap", ".pcapng", ".cap"}
    if file_path.suffix.lower() not in valid_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Accepted: {', '.join(valid_extensions)}",
        )

    # Generate analysis ID
    analysis_id = str(uuid.uuid4())

    logger.info(
        "path_analysis_requested",
        analysis_id=analysis_id,
        path=str(file_path),
        size_bytes=file_path.stat().st_size,
    )

    # Initialize analysis record
    _analyses[analysis_id] = {
        "id": analysis_id,
        "status": "pending",
        "phase": "Queued for processing",
        "progress": 0.0,
        "packets_processed": 0,
        "total_packets": None,
        "elapsed_seconds": 0.0,
        "file_path": str(file_path),
        "original_filename": file_path.name,
        "results": None,
        "error": None,
    }

    # Start background analysis task
    background_tasks.add_task(run_analysis, analysis_id, file_path)

    return AnalysisResponse(
        analysis_id=analysis_id,
        status="pending",
        message=f"Analysis started for {file_path.name}",
    )


@router.get("/analysis/{analysis_id}", response_model=AnalysisStatus)
async def get_analysis_status(analysis_id: str) -> AnalysisStatus:
    """
    Get the current status of an analysis.

    Returns progress information and, when complete, the analysis results.
    """
    if analysis_id not in _analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = _analyses[analysis_id]

    return AnalysisStatus(
        analysis_id=analysis["id"],
        status=analysis["status"],
        phase=analysis["phase"],
        progress=analysis["progress"],
        packets_processed=analysis["packets_processed"],
        total_packets=analysis["total_packets"],
        elapsed_seconds=analysis["elapsed_seconds"],
        error=analysis["error"],
    )


@router.get("/analysis/{analysis_id}/results")
async def get_analysis_results(analysis_id: str) -> dict:
    """
    Get the full results of a completed analysis.
    """
    if analysis_id not in _analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = _analyses[analysis_id]

    if analysis["status"] != "complete":
        raise HTTPException(
            status_code=400,
            detail=f"Analysis not complete. Current status: {analysis['status']}",
        )

    if analysis["results"] is None:
        raise HTTPException(status_code=500, detail="Results not available")

    return analysis["results"]


@router.get("/analysis/{analysis_id}/filters")
async def get_wireshark_filters(analysis_id: str) -> dict:
    """
    Get generated Wireshark filters for an analysis.
    """
    if analysis_id not in _analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = _analyses[analysis_id]

    if analysis["status"] != "complete":
        raise HTTPException(
            status_code=400,
            detail=f"Analysis not complete. Current status: {analysis['status']}",
        )

    results = analysis.get("results", {})
    filters = results.get("wireshark_filters", [])

    return {"analysis_id": analysis_id, "filters": filters}


# =============================================================================
# Background Task
# =============================================================================


async def run_analysis(analysis_id: str, file_path: Path) -> None:
    """
    Background task to run the full analysis pipeline.

    Phases:
    1. Parse PCAP file
    2. Compute statistics
    3. LLM analysis (if API key configured)
    """
    import time

    from backend.analysis.parser import parse_pcap, ParserProgress
    from backend.analysis.statistics import compute_statistics
    from backend.ai.openrouter import get_openrouter_client, LLMError
    from backend.ai.prompts import PromptTemplates
    from backend.ai.context import ContextBuilder

    logger.info("analysis_starting", analysis_id=analysis_id, file_path=str(file_path))

    analysis = _analyses[analysis_id]
    start_time = time.time()

    def update_progress(progress: ParserProgress) -> None:
        """Callback to update analysis progress."""
        analysis["status"] = "parsing"
        analysis["phase"] = "Parsing PCAP file"
        analysis["progress"] = progress.progress * 0.4  # Parsing is 40% of total
        analysis["packets_processed"] = progress.packets_processed
        analysis["total_packets"] = progress.total_packets
        analysis["elapsed_seconds"] = time.time() - start_time

    try:
        # =====================================================================
        # Phase 1: Parse PCAP
        # =====================================================================
        analysis["status"] = "parsing"
        analysis["phase"] = "Parsing PCAP file"

        parse_result = await parse_pcap(
            file_path=file_path,
            progress_callback=update_progress,
            batch_size=settings.packet_batch_size,
        )

        logger.info(
            "parsing_complete",
            analysis_id=analysis_id,
            packets=parse_result.total_packets,
            flows=len(parse_result.flows),
        )

        # =====================================================================
        # Phase 2: Compute Statistics
        # =====================================================================
        analysis["status"] = "analyzing"
        analysis["phase"] = "Computing statistics"
        analysis["progress"] = 0.45

        stats = compute_statistics(parse_result)

        logger.info(
            "statistics_complete",
            analysis_id=analysis_id,
            anomalies=len(stats.anomalies),
        )

        # Build context for LLM
        context_builder = ContextBuilder(stats)
        stats_summary = context_builder.build_stats_summary()
        anomalies_summary = context_builder.build_anomalies_summary()

        # =====================================================================
        # Phase 2.5: Detection Engines
        # =====================================================================
        analysis["status"] = "analyzing"
        analysis["phase"] = "Running detection engines"
        analysis["progress"] = 0.5

        from backend.analysis.detectors import (
            BeaconDetector,
            DNSTunnelDetector,
            ExfiltrationDetector,
            PortScanDetector,
        )

        detectors = [
            BeaconDetector(),
            DNSTunnelDetector(),
            ExfiltrationDetector(),
            PortScanDetector(),
        ]

        all_findings = []
        for detector in detectors:
            try:
                findings = detector.detect(parse_result)
                all_findings.extend(findings)
                logger.debug(
                    "detector_complete",
                    detector=detector.name,
                    findings=len(findings),
                )
            except Exception as e:
                logger.warning(
                    "detector_error",
                    detector=detector.name,
                    error=str(e),
                )

        logger.info(
            "detection_complete",
            analysis_id=analysis_id,
            total_findings=len(all_findings),
        )

        # =====================================================================
        # Phase 2.75: Threat Intelligence Enrichment
        # =====================================================================
        analysis["status"] = "enriching"
        analysis["phase"] = "Threat intelligence enrichment"
        analysis["progress"] = 0.55

        from backend.enrichment.manager import get_enrichment_manager

        enrichment_manager = get_enrichment_manager()
        enrichment_summary = None

        if enrichment_manager.is_configured:
            logger.info("enrichment_starting", analysis_id=analysis_id)

            # Collect IPs and domains from parse result
            all_ips: set[str] = set()
            all_domains: set[str] = set()

            # IPs from flows
            for flow in parse_result.flows.values():
                all_ips.add(flow.src_ip)
                all_ips.add(flow.dst_ip)

            # Domains from DNS queries
            for query in parse_result.dns_queries:
                if query.query_name:
                    all_domains.add(query.query_name)

            # Domains from TLS SNI
            for tls in parse_result.tls_info:
                if tls.sni:
                    all_domains.add(tls.sni)

            # Run enrichment
            enrichment_summary = await enrichment_manager.enrich_indicators(
                ips=all_ips,
                domains=all_domains,
                detector_findings=all_findings,
            )

            logger.info(
                "enrichment_complete",
                analysis_id=analysis_id,
                enriched=len(enrichment_summary.results),
                malicious=enrichment_summary.stats.malicious_found,
            )
        else:
            logger.info(
                "enrichment_skipped",
                analysis_id=analysis_id,
                reason="No threat intel API keys configured",
            )

        # =====================================================================
        # Phase 3: LLM Statistical Analysis (if configured)
        # =====================================================================
        ai_insights = None
        stats_ai_content = None
        llm_client = get_openrouter_client()

        if llm_client.is_configured:
            analysis["status"] = "analyzing"
            analysis["phase"] = "AI-powered statistical analysis"
            analysis["progress"] = 0.6

            logger.info("llm_analysis_starting", analysis_id=analysis_id)

            # Build the prompt
            prompt = PromptTemplates.stats_analysis_prompt(stats_summary)

            # Call LLM
            response = await llm_client.analyze_statistics(
                prompt=prompt,
                system_prompt=PromptTemplates.SYSTEM_STATS_ANALYST,
            )

            if isinstance(response, LLMError):
                logger.warning(
                    "llm_analysis_failed",
                    analysis_id=analysis_id,
                    error=response.message,
                )
                ai_insights = {
                    "status": "error",
                    "error": response.message,
                    "content": None,
                }
            else:
                logger.info(
                    "llm_analysis_complete",
                    analysis_id=analysis_id,
                    tokens_used=response.usage.get("total_tokens", 0),
                )
                ai_insights = {
                    "status": "success",
                    "content": response.content,
                    "model": response.model,
                    "tokens_used": response.usage.get("total_tokens", 0),
                }
                stats_ai_content = response.content
        else:
            logger.info(
                "llm_analysis_skipped",
                analysis_id=analysis_id,
                reason="OpenRouter API key not configured",
            )
            ai_insights = {
                "status": "skipped",
                "error": "OpenRouter API key not configured",
                "content": None,
            }

        # =====================================================================
        # Phase 4: Final Synthesis (if configured)
        # =====================================================================
        synthesis_result = None
        
        if llm_client.is_configured:
            analysis["status"] = "synthesizing"
            analysis["phase"] = "Final AI synthesis"
            analysis["progress"] = 0.8
            
            logger.info("final_synthesis_starting", analysis_id=analysis_id)
            
            from backend.ai.synthesis import (
                get_synthesis_orchestrator,
                SynthesisInput,
            )
            
            # Convert findings to dict format
            findings_for_synthesis = [f.to_dict() for f in all_findings]
            
            # Get enrichment results
            enrichment_results_list = []
            enrichment_stats_dict = {}
            if enrichment_summary:
                enrichment_results_list = enrichment_summary.to_dict().get("results", [])
                enrichment_stats_dict = {
                    "total_enriched": enrichment_summary.stats.total_indicators,
                    "malicious_found": enrichment_summary.stats.malicious_found,
                    "suspicious_found": enrichment_summary.stats.suspicious_found,
                }
            
            # Build top talkers from top_src_ips
            top_talkers = [
                {"ip": t.identifier, "bytes": t.byte_count}
                for t in stats.top_src_ips[:10]
            ]
            
            # Build protocol distribution from protocol_stats
            protocol_distribution = stats.protocol_stats.transport_protocols.copy()
            protocol_distribution.update(stats.protocol_stats.app_protocols)
            
            # Build port distribution from top_dst_ports
            port_distribution = {
                str(t.identifier): t.packet_count
                for t in stats.top_dst_ports[:20]
            }
            
            # Build synthesis input
            synthesis_input = SynthesisInput(
                total_packets=parse_result.total_packets,
                total_bytes=parse_result.total_bytes,
                duration_seconds=parse_result.duration_seconds,
                start_time=parse_result.start_time or "",
                end_time=parse_result.end_time or "",
                unique_ips=stats.unique_src_ips + stats.unique_dst_ips,
                total_flows=stats.total_flows,
                findings=findings_for_synthesis,
                enrichment_results=enrichment_results_list,
                enrichment_stats=enrichment_stats_dict,
                stats_ai_content=stats_ai_content,
                top_talkers=top_talkers,
                protocol_distribution=protocol_distribution,
                port_distribution=port_distribution,
                anomalies=[a.to_dict() for a in stats.anomalies],
            )
            
            # Run synthesis
            synthesis_orchestrator = get_synthesis_orchestrator()
            synth_result = await synthesis_orchestrator.synthesize(synthesis_input)
            
            if synth_result.success:
                logger.info(
                    "final_synthesis_complete",
                    analysis_id=analysis_id,
                    tokens_used=synth_result.tokens_used,
                    threat_level=synth_result.threat_level,
                )
                synthesis_result = synth_result.to_dict()
            else:
                logger.warning(
                    "final_synthesis_failed",
                    analysis_id=analysis_id,
                    error=synth_result.error,
                )
                synthesis_result = {
                    "success": False,
                    "error": synth_result.error,
                }
        else:
            logger.info(
                "final_synthesis_skipped",
                analysis_id=analysis_id,
                reason="OpenRouter API key not configured",
            )

        # =====================================================================
        # Phase 5: Generate Enhanced Wireshark Filters
        # =====================================================================
        analysis["status"] = "finalizing"
        analysis["phase"] = "Generating Wireshark filters"
        analysis["progress"] = 0.95
        
        from backend.output.wireshark import WiresharkFilterGenerator, FilterCategory
        
        filter_generator = WiresharkFilterGenerator()
        
        # Generate from detection findings
        findings_data = [f.to_dict() for f in all_findings]
        filter_generator.generate_from_findings(findings_data)
        
        # Generate from enrichment results
        if enrichment_summary:
            enrichment_results_for_filters = enrichment_summary.to_dict().get("results", [])
            filter_generator.generate_from_enrichment(enrichment_results_for_filters)
        
        # Add legacy filters from stats anomalies
        legacy_filters = _generate_wireshark_filters(stats)
        for lf in legacy_filters:
            filter_generator.add_raw_filter(
                filter_text=lf.get("filter", ""),
                name=lf.get("name", "Anomaly"),
                description=lf.get("description", ""),
                category=FilterCategory.CUSTOM,
                severity=lf.get("severity", "medium"),
            )
        
        # Add AI-recommended filters if synthesis was successful
        if synthesis_result and synthesis_result.get("success"):
            for ai_filter in synthesis_result.get("recommended_filters", [])[:5]:
                if ai_filter:
                    filter_generator.add_raw_filter(
                        filter_text=ai_filter,
                        name=f"AI Recommended: {ai_filter[:30]}...",
                        description="Filter recommended by AI synthesis",
                        category=FilterCategory.CUSTOM,
                        severity="high",
                        confidence=0.7,
                    )
        
        wireshark_filters = filter_generator.to_list()

        # =====================================================================
        # Build Results
        # =====================================================================
        analysis["status"] = "complete"
        analysis["phase"] = "Analysis complete"
        analysis["progress"] = 1.0
        analysis["elapsed_seconds"] = time.time() - start_time
        
        # Sort findings by severity (critical first) then by confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_data.sort(
            key=lambda f: (severity_order.get(f["severity"], 5), -f["confidence"])
        )

        # Build enrichment data
        enrichment_data = None
        if enrichment_summary:
            enrichment_data = enrichment_summary.to_dict()

        analysis["results"] = {
            "summary": {
                "total_packets": parse_result.total_packets,
                "total_bytes": parse_result.total_bytes,
                "duration_seconds": parse_result.duration_seconds,
                "start_time": parse_result.start_time,
                "end_time": parse_result.end_time,
                "unique_ips": stats.unique_src_ips + stats.unique_dst_ips,
                "total_flows": stats.total_flows,
                "detections": len(all_findings),
                "enriched_indicators": len(enrichment_summary.results) if enrichment_summary else 0,
                "malicious_indicators": enrichment_summary.stats.malicious_found if enrichment_summary else 0,
                "threat_level": synthesis_result.get("threat_level", "unknown") if synthesis_result else "unknown",
            },
            "statistics": stats.to_dict(),
            "detections": findings_data,
            "enrichment": enrichment_data,
            "ai_insights": ai_insights,
            "synthesis": synthesis_result,
            "wireshark_filters": wireshark_filters,
        }

        logger.info(
            "analysis_complete",
            analysis_id=analysis_id,
            packets=parse_result.total_packets,
            anomalies=len(stats.anomalies),
            detections=len(all_findings),
            filters=len(wireshark_filters),
            duration=analysis["elapsed_seconds"],
        )

    except Exception as e:
        logger.error(
            "analysis_failed",
            analysis_id=analysis_id,
            error=str(e),
            exc_info=True,
        )
        analysis["status"] = "error"
        analysis["phase"] = "Analysis failed"
        analysis["error"] = str(e)
        analysis["elapsed_seconds"] = time.time() - start_time


def _generate_wireshark_filters(stats) -> list[dict]:
    """
    Generate Wireshark display filters from analysis results.

    Args:
        stats: TrafficStatistics object

    Returns:
        List of filter dictionaries
    """
    filters = []

    for anomaly in stats.anomalies:
        if anomaly.category == "beacon":
            # Filter for beacon traffic
            indicators = anomaly.indicators
            if "flow" in indicators:
                flow = indicators["flow"]
                # Parse flow key: src:port->dst:port/proto
                parts = flow.split("->")
                if len(parts) == 2:
                    src = parts[0].split(":")[0]
                    dst_parts = parts[1].split("/")
                    dst = dst_parts[0].split(":")[0]
                    filters.append({
                        "name": f"Beacon: {src} → {dst}",
                        "description": anomaly.description,
                        "filter": f"ip.addr == {src} && ip.addr == {dst}",
                        "severity": anomaly.severity,
                        "category": "beacon",
                    })

        elif anomaly.category == "exfiltration":
            # Filter for exfiltration traffic
            for ip in anomaly.affected_ips:
                if not _is_private_ip(ip):
                    filters.append({
                        "name": f"Exfiltration to {ip}",
                        "description": anomaly.description,
                        "filter": f"ip.dst == {ip}",
                        "severity": anomaly.severity,
                        "category": "exfiltration",
                    })

        elif anomaly.category == "dns_tunnel":
            # Filter for DNS tunneling
            domain = anomaly.indicators.get("domain", "")
            if domain:
                filters.append({
                    "name": f"DNS Tunnel: {domain}",
                    "description": anomaly.description,
                    "filter": f'dns.qry.name contains "{domain}"',
                    "severity": anomaly.severity,
                    "category": "dns_tunnel",
                })

        elif anomaly.category == "port_scan":
            # Filter for port scanning
            for ip in anomaly.affected_ips:
                filters.append({
                    "name": f"Port Scan from {ip}",
                    "description": anomaly.description,
                    "filter": f"ip.src == {ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
                    "severity": anomaly.severity,
                    "category": "port_scan",
                })

        elif anomaly.category == "suspicious_dns":
            # Filter for suspicious DNS
            tld = anomaly.indicators.get("tld", "")
            if tld:
                filters.append({
                    "name": f"Suspicious TLD: {tld}",
                    "description": anomaly.description,
                    "filter": f'dns.qry.name contains "{tld}"',
                    "severity": anomaly.severity,
                    "category": "suspicious_dns",
                })

    return filters


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except (ValueError, IndexError):
        return False


# =============================================================================
# PCAP File Browser Endpoints
# =============================================================================

class PcapFileInfo(BaseModel):
    """Information about a PCAP file."""
    
    name: str = Field(..., description="File name")
    path: str = Field(..., description="Full file path")
    size: int = Field(..., description="File size in bytes")
    modified: str = Field(..., description="Last modified timestamp (ISO format)")


class PcapFilesResponse(BaseModel):
    """Response containing list of PCAP files."""
    
    folder: str = Field(..., description="Folder path being scanned")
    files: list[PcapFileInfo] = Field(default_factory=list, description="List of PCAP files")


# Default PCAP folder (can be configured)
PCAP_FOLDER = Path.home() / "SPR600" / "pcaps"


@router.get("/pcaps", response_model=PcapFilesResponse)
async def list_pcap_files() -> PcapFilesResponse:
    """
    List all PCAP files in the configured folder.
    
    Returns a list of PCAP/PCAPNG files with their metadata.
    """
    import datetime
    
    # Ensure folder exists
    if not PCAP_FOLDER.exists():
        PCAP_FOLDER.mkdir(parents=True, exist_ok=True)
        logger.info("pcap_folder_created", path=str(PCAP_FOLDER))
    
    files: list[PcapFileInfo] = []
    valid_extensions = {".pcap", ".pcapng", ".cap"}
    
    for file_path in PCAP_FOLDER.iterdir():
        if file_path.is_file() and file_path.suffix.lower() in valid_extensions:
            stat = file_path.stat()
            files.append(PcapFileInfo(
                name=file_path.name,
                path=str(file_path),
                size=stat.st_size,
                modified=datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            ))
    
    # Sort by modified time descending (newest first)
    files.sort(key=lambda f: f.modified, reverse=True)
    
    logger.info("pcap_files_listed", folder=str(PCAP_FOLDER), count=len(files))
    
    return PcapFilesResponse(folder=str(PCAP_FOLDER), files=files)
