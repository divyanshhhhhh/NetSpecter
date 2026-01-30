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
    # Phase 4: Smart Indicator Filtering + Cascading Enrichment
    # =========================================================================
    from backend.analysis.smart_filter import get_smart_filter, FilteredIndicators
    from backend.enrichment.cascading import (
        get_cascading_enrichment,
        CascadingResult,
        ProgressUpdate,
    )
    
    console.print_phase_header(
        "enrichment",
        "PHASE 4: Smart Indicator Filtering & Enrichment",
        "Filter by conversation volume, legit domains, typosquatting detection"
    )
    
    cascading = get_cascading_enrichment()
    enrichment_result: CascadingResult | None = None
    smart_filter = get_smart_filter()
    
    # Interactive filter configuration loop
    filter_confirmed = False
    while not filter_confirmed:
        console.console.print("[bold cyan]Configure traffic filtering:[/bold cyan]")
        console.console.print("  [dim]Filter conversations by traffic volume to select indicators[/dim]")
        console.console.print()
        
        # Ask for direction: top (highest volume) or bottom (lowest volume)
        console.console.print("  [1] Top N% (highest traffic volume - typical for investigation)")
        console.console.print("  [2] Bottom N% (lowest traffic volume - look for hidden channels)")
        console.console.print("  [s] Skip enrichment entirely")
        direction_input = console.console.input("[bold]Select [1/2/s] (default: 1):[/bold] ").strip().lower()
        
        if direction_input == "s":
            console.print_info("Enrichment skipped by user")
            filter_confirmed = True
            enrichment_result = None
            break
        
        use_top = direction_input != "2"
        
        # Ask for percentage
        default_pct = 40
        pct_input = console.console.input(f"[bold]Percentage to analyze (default: {default_pct}%):[/bold] ").strip()
        try:
            percent = int(pct_input) if pct_input else default_pct
            percent = max(1, min(100, percent))  # Clamp to 1-100
        except ValueError:
            percent = default_pct
        
        console.console.print()
        direction_text = "top" if use_top else "bottom"
        console.print_info(f"Filtering {direction_text} {percent}% of conversations by traffic volume...")
        
        # Run smart filter with user's settings
        filtered_indicators: FilteredIndicators = smart_filter.filter_indicators(
            flows=parse_result.flows,
            dns_queries=parse_result.dns_queries,
            tls_info=parse_result.tls_info,
            top_percent=percent / 100.0,
            use_top=use_top,
        )
        
        # Print filtering summary and ask for confirmation
        console.console.print()
        console.console.print("[bold bright_white]📊 Filtering Results:[/bold bright_white]")
        console.print_info(f"Total conversations: {filtered_indicators.total_conversations}")
        console.print_info(f"Analyzed ({direction_text} {percent}%): {filtered_indicators.top_conversations_analyzed} conversations")
        console.console.print()
        console.console.print(f"  [bold cyan]Public IPs to check:[/bold cyan] [bright_white]{len(filtered_indicators.public_ips)}[/bright_white]")
        console.console.print(f"  [bold cyan]Domains to check:[/bold cyan] [bright_white]{len(filtered_indicators.domains)}[/bright_white]")
        console.console.print(f"  [dim]Filtered by legitdomains.txt: {filtered_indicators.domains_filtered_by_legit}[/dim]")
        
        if filtered_indicators.typosquat_suspects:
            console.print_warning(
                f"Typosquatting detected: {', '.join(list(filtered_indicators.typosquat_suspects)[:5])}"
            )
        
        # Confirm before proceeding
        console.console.print()
        proceed = console.console.input("[bold]Proceed with enrichment? [Y/n] (n = re-configure):[/bold] ").strip().lower()
        
        if proceed != "n":
            filter_confirmed = True
        else:
            console.console.print()
            console.print_info("Re-configuring filter settings...")
            console.console.print()
    
    # Proceed with enrichment if confirmed and not skipped
    skip_enrichment = (enrichment_result is not None) or not filter_confirmed
    
    if skip_enrichment:
        pass  # Already handled skip case in loop
    elif not cascading.is_configured:
        console.print_enrichment_skipped("No threat intel API keys configured")
    elif filtered_indicators.total_indicators() == 0:
        console.print_info("No indicators to check after smart filtering")
    else:
        console.print_cascading_enrichment_start(
            len(filtered_indicators.public_ips),
            len(filtered_indicators.domains)
        )
        
        # Track current step for console output
        current_step = {"step": None, "otx_flagged": 0, "abuse_flagged": 0, "vt_malicious": 0}
        
        def progress_callback(update: ProgressUpdate) -> None:
            """Handle enrichment progress updates."""
            # Print step header if step changed
            if current_step["step"] != update.step:
                current_step["step"] = update.step
                
                if update.step == "otx":
                    console.print_enrichment_step_start(
                        "1: AlienVault OTX",
                        "Querying selected indicators for threat pulses",
                        "10,000/hour"
                    )
                elif update.step == "abuseipdb":
                    # Print OTX summary before moving on
                    console.print_enrichment_step_complete(
                        "OTX",
                        len(filtered_indicators.public_ips) + len(filtered_indicators.domains),
                        current_step["otx_flagged"]
                    )
                    console.print_enrichment_step_start(
                        "2: AbuseIPDB",
                        "Checking OTX-flagged IPs for abuse reports",
                        "1,000/day"
                    )
                elif update.step == "virustotal":
                    # Print AbuseIPDB summary
                    console.print_enrichment_step_complete(
                        "AbuseIPDB",
                        update.total,
                        current_step["abuse_flagged"]
                    )
                    console.print_enrichment_step_start(
                        "3: VirusTotal",
                        "Deep scanning flagged indicators (max 10)",
                        "4/min"
                    )
            
            # Print progress line
            console.print_enrichment_progress(
                step=update.step,
                current=update.current,
                total=update.total,
                indicator=update.indicator,
                is_flagged=update.is_flagged,
                threat_level=update.threat_level,
                details=update.details,
            )
            
            # Track flagged counts
            if update.is_flagged:
                if update.step == "otx":
                    current_step["otx_flagged"] += 1
                elif update.step == "abuseipdb":
                    current_step["abuse_flagged"] += 1
                elif update.step == "virustotal" and update.threat_level == "malicious":
                    current_step["vt_malicious"] += 1
        
        enrichment_result = await cascading.run(
            ips=filtered_indicators.public_ips,
            domains=filtered_indicators.domains,
            typosquat_suspects=filtered_indicators.typosquat_suspects,
            progress_callback=progress_callback,
        )
        
        # Print final step summary
        if current_step["step"] == "virustotal":
            console.print_enrichment_step_complete(
                "VirusTotal",
                enrichment_result.stats.vt_checked,
                enrichment_result.stats.vt_malicious
            )
        elif current_step["step"] == "abuseipdb":
            console.print_enrichment_step_complete(
                "AbuseIPDB",
                enrichment_result.stats.abuseipdb_checked,
                current_step["abuse_flagged"]
            )
        elif current_step["step"] == "otx":
            console.print_enrichment_step_complete(
                "OTX",
                enrichment_result.stats.otx_checked,
                current_step["otx_flagged"]
            )
        
        # Print stats and flagged indicators
        console.print_enrichment_stats(enrichment_result.stats.to_dict())
        console.print_flagged_indicators(enrichment_result.flagged_indicators)
        
        console.print_success(f"Enrichment complete: {enrichment_result.stats.total_malicious} malicious, {enrichment_result.stats.total_suspicious} suspicious")
    
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
        console.print_subphase("Running final synthesis with DeepSeek R1...")
        
        from backend.ai.synthesis import get_synthesis_orchestrator, SynthesisInput
        
        findings_for_synthesis = [f.to_dict() for f in all_findings]
        
        enrichment_results_list = []
        enrichment_stats_dict = {}
        if enrichment_result:
            enrichment_results_list = [r.to_dict() for r in enrichment_result.results]
            enrichment_stats_dict = {
                "total_enriched": enrichment_result.stats.total_indicators,
                "malicious_found": enrichment_result.stats.total_malicious,
                "suspicious_found": enrichment_result.stats.total_suspicious,
                "flagged_indicators": enrichment_result.flagged_indicators,
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
    
    if enrichment_result:
        enrichment_results_for_filters = [r.to_dict() for r in enrichment_result.results]
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
        "enriched_indicators": len(enrichment_result.results) if enrichment_result else 0,
        "malicious_indicators": enrichment_result.stats.total_malicious if enrichment_result else 0,
        "threat_level": synthesis_result.get("threat_level", "unknown") if synthesis_result else "unknown",
        "wireshark_filters": wireshark_filters,
    }
    
    console.print_analysis_complete(elapsed, summary)
    
    return {
        "summary": summary,
        "statistics": stats.to_dict(),
        "detections": findings_data,
        "enrichment": enrichment_result.to_dict() if enrichment_result else None,
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
        
        # Save JSON results if output file specified
        if args.output:
            import json
            output_path = Path(args.output)
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            console.print_success(f"Results saved to {output_path}")
        
        # Prompt to save markdown report
        if console.prompt_save_report():
            from backend.output.report import get_report_generator, save_report
            
            report_gen = get_report_generator()
            report_content = report_gen.generate(
                pcap_name=selected_file["name"],
                results=results,
            )
            report_path = save_report(report_content, selected_file["path"])
            console.print_report_saved(str(report_path))
        
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
