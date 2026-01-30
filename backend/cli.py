#!/usr/bin/env python3
"""
NetSpecter CLI - Command Line Interface

Interactive command-line tool for network packet analysis.
Run with a directory path to scan for PCAP files and analyze them.

Usage:
    netspecter [directory]
    netspecter /path/to/pcaps
    netspecter  # Uses default ~/SPR600/pcaps
"""

import argparse
import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path

from backend.output.console import get_console, NetSpecterConsole


# =============================================================================
# Directory Scanning
# =============================================================================


def scan_directory(directory: Path) -> list[dict]:
    """
    Scan directory for PCAP files.
    
    Args:
        directory: Path to scan
        
    Returns:
        List of file info dictionaries
    """
    pcap_extensions = {".pcap", ".pcapng", ".cap"}
    files = []
    
    if not directory.exists():
        return []
    
    for path in directory.iterdir():
        if path.is_file() and path.suffix.lower() in pcap_extensions:
            stat = path.stat()
            size = stat.st_size
            modified = datetime.fromtimestamp(stat.st_mtime)
            
            # Format size
            if size < 1024:
                size_human = f"{size} B"
            elif size < 1024 ** 2:
                size_human = f"{size / 1024:.1f} KB"
            elif size < 1024 ** 3:
                size_human = f"{size / (1024 ** 2):.1f} MB"
            else:
                size_human = f"{size / (1024 ** 3):.2f} GB"
            
            files.append({
                "name": path.name,
                "path": path,
                "size": size,
                "size_human": size_human,
                "modified": modified.strftime("%Y-%m-%d %H:%M"),
            })
    
    # Sort by modification time (newest first)
    files.sort(key=lambda x: x["modified"], reverse=True)
    return files


# =============================================================================
# Analysis Runner
# =============================================================================


async def run_analysis(file_path: Path, console: NetSpecterConsole) -> dict:
    """
    Run the full analysis pipeline with console output.
    
    Args:
        file_path: Path to PCAP file
        console: Console instance for output
        
    Returns:
        Analysis results dictionary
    """
    from backend.analysis.parser import parse_pcap, ParserProgress
    from backend.analysis.statistics import compute_statistics
    from backend.ai.openrouter import get_openrouter_client, LLMError
    from backend.ai.prompts import PromptTemplates
    from backend.ai.context import ContextBuilder
    from backend.config import settings
    
    start_time = time.time()
    results = {}
    
    # =========================================================================
    # Phase 1: Parse PCAP
    # =========================================================================
    file_size = file_path.stat().st_size
    if file_size < 1024:
        size_str = f"{file_size} B"
    elif file_size < 1024 ** 2:
        size_str = f"{file_size / 1024:.1f} KB"
    elif file_size < 1024 ** 3:
        size_str = f"{file_size / (1024 ** 2):.1f} MB"
    else:
        size_str = f"{file_size / (1024 ** 3):.2f} GB"
    
    console.print_parsing_start(file_path.name, size_str)
    
    # Create progress bar
    progress = console.create_progress()
    parse_task = None
    
    def update_progress(prog: ParserProgress) -> None:
        """Callback to update progress bar."""
        nonlocal parse_task
        if parse_task is None:
            parse_task = progress.add_task(
                "[cyan]Parsing packets...",
                total=100,
                packets=0,
            )
        progress.update(
            parse_task,
            completed=prog.progress * 100,
            packets=prog.packets_processed,
        )
    
    with progress:
        parse_result = await parse_pcap(
            file_path=file_path,
            progress_callback=update_progress,
            batch_size=settings.packet_batch_size,
        )
    
    console.print_parsing_complete(
        packets=parse_result.total_packets,
        bytes_total=parse_result.total_bytes,
        duration=parse_result.duration_seconds,
        flows=len(parse_result.flows),
    )
    
    # =========================================================================
    # Phase 2: Compute Statistics
    # =========================================================================
    console.print_statistics_start()
    
    stats = compute_statistics(parse_result)
    console.print_success(f"Statistics computed: {len(stats.anomalies)} anomalies detected")
    console.print_statistics(stats.to_dict())
    
    # =========================================================================
    # Phase 3: Run Detection Engines
    # =========================================================================
    console.print_detection_start()
    
    from backend.analysis.detectors import (
        BeaconDetector,
        DNSTunnelDetector,
        ExfiltrationDetector,
        PortScanDetector,
    )
    
    detectors = [
        ("Beacon Detector", BeaconDetector()),
        ("DNS Tunnel Detector", DNSTunnelDetector()),
        ("Exfiltration Detector", ExfiltrationDetector()),
        ("Port Scan Detector", PortScanDetector()),
    ]
    
    all_findings = []
    for name, detector in detectors:
        try:
            findings = detector.detect(parse_result)
            all_findings.extend(findings)
            console.print_detector_result(name, len(findings))
        except Exception as e:
            console.print_error(f"{name}: Error - {str(e)}")
    
    console.print_findings([f.to_dict() for f in all_findings])
    
    # =========================================================================
    # Phase 4: Threat Intelligence Enrichment
    # =========================================================================
    console.print_enrichment_start()
    
    from backend.enrichment.manager import get_enrichment_manager
    
    enrichment_manager = get_enrichment_manager()
    enrichment_summary = None
    
    if enrichment_manager.is_configured:
        console.print_info("Threat intelligence APIs configured, enriching indicators...")
        
        # Collect IPs and domains
        all_ips: set[str] = set()
        all_domains: set[str] = set()
        
        for flow in parse_result.flows.values():
            all_ips.add(flow.src_ip)
            all_ips.add(flow.dst_ip)
        
        for query in parse_result.dns_queries:
            if query.query_name:
                all_domains.add(query.query_name)
        
        for tls in parse_result.tls_info:
            if tls.sni:
                all_domains.add(tls.sni)
        
        enrichment_summary = await enrichment_manager.enrich_indicators(
            ips=all_ips,
            domains=all_domains,
            detector_findings=all_findings,
        )
        
        console.print_success(f"Enrichment complete: {len(enrichment_summary.results)} indicators checked")
        console.print_enrichment_results(enrichment_summary.to_dict())
    else:
        console.print_enrichment_skipped("No threat intel API keys configured")
    
    # =========================================================================
    # Phase 5: AI Analysis
    # =========================================================================
    console.print_ai_analysis_start()
    
    # Build context for LLM
    context_builder = ContextBuilder(stats)
    stats_summary = context_builder.build_stats_summary()
    
    llm_client = get_openrouter_client()
    ai_insights = None
    stats_ai_content = None
    
    if llm_client.is_configured:
        console.print_info("OpenRouter API configured, running AI analysis...")
        
        prompt = PromptTemplates.stats_analysis_prompt(stats_summary)
        response = await llm_client.analyze_statistics(
            prompt=prompt,
            system_prompt=PromptTemplates.SYSTEM_STATS_ANALYST,
        )
        
        if isinstance(response, LLMError):
            console.print_warning(f"AI analysis failed: {response.message}")
            ai_insights = {"status": "error", "error": response.message}
        else:
            console.print_success(f"AI analysis complete ({response.usage.get('total_tokens', 0)} tokens)")
            ai_insights = {
                "status": "success",
                "content": response.content,
                "model": response.model,
                "tokens_used": response.usage.get("total_tokens", 0),
            }
            stats_ai_content = response.content
            console.print_ai_insights(ai_insights)
    else:
        console.print_ai_skipped("OpenRouter API key not configured")
        ai_insights = {"status": "skipped"}
    
    # =========================================================================
    # Phase 6: Final Synthesis
    # =========================================================================
    synthesis_result = None
    
    if llm_client.is_configured:
        console.print_subphase("Running final synthesis with DeepSeek R1T2 Chimera...")
        
        from backend.ai.synthesis import get_synthesis_orchestrator, SynthesisInput
        
        findings_for_synthesis = [f.to_dict() for f in all_findings]
        
        enrichment_results_list = []
        enrichment_stats_dict = {}
        if enrichment_summary:
            enrichment_results_list = enrichment_summary.to_dict().get("results", [])
            enrichment_stats_dict = {
                "total_enriched": enrichment_summary.stats.total_indicators,
                "malicious_found": enrichment_summary.stats.malicious_found,
                "suspicious_found": enrichment_summary.stats.suspicious_found,
            }
        
        top_talkers = [
            {"ip": t.identifier, "bytes": t.byte_count}
            for t in stats.top_src_ips[:10]
        ]
        
        protocol_distribution = stats.protocol_stats.transport_protocols.copy()
        protocol_distribution.update(stats.protocol_stats.app_protocols)
        
        port_distribution = {
            str(t.identifier): t.packet_count
            for t in stats.top_dst_ports[:20]
        }
        
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
        
        synthesis_orchestrator = get_synthesis_orchestrator()
        synth_result = await synthesis_orchestrator.synthesize(synthesis_input)
        
        if synth_result.success:
            console.print_success(f"Synthesis complete ({synth_result.tokens_used} tokens)")
            synthesis_result = synth_result.to_dict()
            console.print_synthesis(synthesis_result)
        else:
            console.print_warning(f"Synthesis failed: {synth_result.error}")
            synthesis_result = {"success": False, "error": synth_result.error}
    
    # =========================================================================
    # Phase 7: Generate Wireshark Filters
    # =========================================================================
    from backend.output.wireshark import WiresharkFilterGenerator, FilterCategory
    
    filter_generator = WiresharkFilterGenerator()
    
    findings_data = [f.to_dict() for f in all_findings]
    filter_generator.generate_from_findings(findings_data)
    
    if enrichment_summary:
        enrichment_results_for_filters = enrichment_summary.to_dict().get("results", [])
        filter_generator.generate_from_enrichment(enrichment_results_for_filters)
    
    # Add AI-recommended filters
    if synthesis_result and synthesis_result.get("success"):
        for ai_filter in synthesis_result.get("recommended_filters", [])[:5]:
            if ai_filter:
                filter_generator.add_raw_filter(
                    filter_text=ai_filter,
                    name=f"AI: {ai_filter[:30]}...",
                    description="Filter recommended by AI synthesis",
                    category=FilterCategory.CUSTOM,
                    severity="high",
                    confidence=0.7,
                )
    
    wireshark_filters = filter_generator.to_list()
    console.print_wireshark_filters(wireshark_filters)
    
    # =========================================================================
    # Build Final Results
    # =========================================================================
    elapsed = time.time() - start_time
    
    summary = {
        "total_packets": parse_result.total_packets,
        "total_bytes": parse_result.total_bytes,
        "duration_seconds": parse_result.duration_seconds,
        "detections": len(all_findings),
        "enriched_indicators": len(enrichment_summary.results) if enrichment_summary else 0,
        "malicious_indicators": enrichment_summary.stats.malicious_found if enrichment_summary else 0,
        "threat_level": synthesis_result.get("threat_level", "unknown") if synthesis_result else "unknown",
        "wireshark_filters": wireshark_filters,
    }
    
    console.print_analysis_complete(elapsed, summary)
    
    return {
        "summary": summary,
        "statistics": stats.to_dict(),
        "detections": findings_data,
        "enrichment": enrichment_summary.to_dict() if enrichment_summary else None,
        "ai_insights": ai_insights,
        "synthesis": synthesis_result,
        "wireshark_filters": wireshark_filters,
    }


# =============================================================================
# Main Entry Point
# =============================================================================


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="NetSpecter - Network Packet Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    netspecter                    # Use default directory ~/SPR600/pcaps
    netspecter /path/to/pcaps     # Scan specific directory
    netspecter -o results.json    # Save results to JSON file
""",
    )
    
    parser.add_argument(
        "directory",
        nargs="?",
        default=str(Path.home() / "SPR600" / "pcaps"),
        help="Directory to scan for PCAP files (default: ~/SPR600/pcaps)",
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Save analysis results to JSON file",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    args = parser.parse_args()
    
    # Initialize console
    console = get_console()
    
    # Clear screen and print banner
    console.clear()
    console.print_banner()
    
    # Scan directory
    directory = Path(args.directory).expanduser().resolve()
    
    if not directory.exists():
        console.print_error(f"Directory not found: {directory}")
        return 1
    
    if not directory.is_dir():
        console.print_error(f"Path is not a directory: {directory}")
        return 1
    
    console.print_directory_scan(directory)
    files = scan_directory(directory)
    
    if not files:
        console.print_error(f"No PCAP files found in {directory}")
        console.console.print("\n[dim]Supported extensions: .pcap, .pcapng, .cap[/dim]")
        return 1
    
    console.print_pcap_table(files)
    
    # Interactive file selection loop
    while True:
        selection = console.prompt_file_selection(len(files))
        
        if selection.lower() == "q":
            console.console.print("\n[dim]Goodbye![/dim]")
            return 0
        
        try:
            index = int(selection) - 1
            if 0 <= index < len(files):
                selected_file = files[index]
                break
            else:
                console.print_error(f"Invalid selection. Please enter 1-{len(files)}")
        except ValueError:
            console.print_error("Please enter a number or 'q' to quit")
    
    # Run analysis
    console.console.print()
    console.print_separator()
    console.console.print()
    console.console.print(f"[bold bright_white]🔍 ANALYZING:[/bold bright_white] {selected_file['name']} ({selected_file['size_human']})")
    
    try:
        results = asyncio.run(run_analysis(selected_file["path"], console))
        
        # Save results if output file specified
        if args.output:
            import json
            output_path = Path(args.output)
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            console.print_success(f"Results saved to {output_path}")
        
        return 0
        
    except KeyboardInterrupt:
        console.console.print("\n\n[yellow]Analysis interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print_analysis_error(str(e))
        if args.verbose:
            import traceback
            console.console.print(f"\n[dim]{traceback.format_exc()}[/dim]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
