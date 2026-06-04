"""
NetSpecter Console Output Module

Rich console formatting for the CLI interface.
Provides colorful, structured output for analysis results.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.markdown import Markdown
from rich.box import ROUNDED, HEAVY, DOUBLE
from rich import print as rprint


# =============================================================================
# Constants
# =============================================================================

VERSION = "0.1.0"
AUTHOR = "Divyansh Pandya"
LICENSE = "MIT License"

# ASCII Art Banner
BANNER = r"""
 ███╗   ██╗███████╗████████╗███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ 
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║   ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""

# Severity colors
SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "info": "cyan",
}

# Phase icons
PHASE_ICONS = {
    "parsing": "📦",
    "statistics": "📊",
    "detection": "🔍",
    "enrichment": "🌐",
    "ai_analysis": "🤖",
    "synthesis": "🧠",
    "filters": "🎯",
    "complete": "✅",
    "error": "❌",
}


# =============================================================================
# Console Display Class
# =============================================================================


class NetSpecterConsole:
    """Rich console interface for NetSpecter CLI."""

    def __init__(self):
        """Initialize the console."""
        self.console = Console()
        self._width = self.console.width

    def clear(self) -> None:
        """Clear the console."""
        self.console.clear()

    def print_banner(self) -> None:
        """Print the NetSpecter ASCII art banner."""
        # Print ASCII art in cyan
        self.console.print(BANNER, style="cyan bold")
        
        # Print version and author info
        info_text = Text()
        info_text.append(f"v{VERSION}", style="bright_white bold")
        info_text.append(" | ", style="dim")
        info_text.append(f"Author: {AUTHOR}", style="bright_blue")
        info_text.append(" | ", style="dim")
        info_text.append(LICENSE, style="bright_green")
        self.console.print(info_text, justify="center")
        self.console.print()

        # Print description panel
        description = """[bold cyan]Network Packet Analysis Tool for Cybersecurity Investigation[/bold cyan]

Automates deep packet inspection through multi-phase analysis:

  [yellow]•[/yellow] [white]Statistical Analysis[/white] - Protocol distribution, top talkers, timeline
  [yellow]•[/yellow] [white]Behavioral Detection[/white] - C2 beacons, DNS tunneling, data exfiltration, port scans
  [yellow]•[/yellow] [white]Threat Intelligence[/white] - VirusTotal, AbuseIPDB, AlienVault OTX enrichment
  [yellow]•[/yellow] [white]AI-Powered Analysis[/white] - LLM-based anomaly detection and synthesis
  [yellow]•[/yellow] [white]Actionable Output[/white] - Wireshark filters for manual investigation

[dim]All output is scrollable - scroll up to review previous phases[/dim]"""

        self.console.print(Panel(
            description,
            border_style="bright_blue",
            padding=(1, 2),
        ))
        self.console.print()

    def print_separator(self, style: str = "dim") -> None:
        """Print a horizontal separator line."""
        self.console.print("─" * self._width, style=style)

    def print_phase_header(self, phase: str, title: str, description: str = "") -> None:
        """Print a phase header with icon and description."""
        icon = PHASE_ICONS.get(phase, "▶")
        
        self.console.print()
        self.console.print(f"{'═' * self._width}", style="bright_blue")
        self.console.print(f" {icon} [bold bright_white]{title}[/bold bright_white]")
        if description:
            self.console.print(f"    [dim]{description}[/dim]")
        self.console.print(f"{'═' * self._width}", style="bright_blue")
        self.console.print()

    def print_subphase(self, text: str, style: str = "dim") -> None:
        """Print a subphase indicator."""
        self.console.print(f"  → {text}", style=style)

    def print_success(self, text: str) -> None:
        """Print a success message."""
        self.console.print(f"  [green]✓[/green] {text}")

    def print_warning(self, text: str) -> None:
        """Print a warning message."""
        self.console.print(f"  [yellow]⚠[/yellow] {text}")

    def print_error(self, text: str) -> None:
        """Print an error message."""
        self.console.print(f"  [red]✗[/red] {text}")

    def print_info(self, text: str) -> None:
        """Print an info message."""
        self.console.print(f"  [cyan]ℹ[/cyan] {text}")

    # =========================================================================
    # Directory and File Listing
    # =========================================================================

    def print_directory_scan(self, directory: Path) -> None:
        """Print directory scanning message."""
        self.console.print(f"[dim]📁 Scanning directory:[/dim] [bright_white]{directory}[/bright_white]")
        self.console.print()

    def print_pcap_table(self, files: list[dict]) -> None:
        """Print table of PCAP files found."""
        if not files:
            self.console.print("[yellow]No PCAP files found in directory.[/yellow]")
            return

        table = Table(
            title="Available PCAP Files",
            box=ROUNDED,
            border_style="bright_blue",
            header_style="bold bright_white",
            title_style="bold cyan",
        )
        
        table.add_column("#", style="bright_yellow", justify="center", width=4)
        table.add_column("Filename", style="bright_white", min_width=30)
        table.add_column("Size", style="bright_green", justify="right", width=12)
        table.add_column("Modified", style="dim", width=20)

        for i, f in enumerate(files, 1):
            table.add_row(
                str(i),
                f["name"],
                f["size_human"],
                f["modified"],
            )

        self.console.print(table)
        self.console.print()

    def prompt_file_selection(self, max_num: int) -> str:
        """Prompt user to select a file."""
        return self.console.input(
            f"[bold bright_white]Select a file to analyze (1-{max_num})[/bold bright_white] or [dim]'q' to quit[/dim]: "
        )

    # =========================================================================
    # Analysis Progress
    # =========================================================================

    def create_progress(self) -> Progress:
        """Create a progress bar for parsing."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("[bright_cyan]{task.fields[packets]:,}[/bright_cyan] packets"),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )

    def print_parsing_start(self, filename: str, size: str) -> None:
        """Print parsing start message."""
        self.print_phase_header(
            "parsing",
            "PHASE 1: Parsing PCAP File",
            f"Reading packets from {filename} ({size})"
        )
        self.print_info("Streaming packets in batches of 10,000 for memory efficiency")
        self.print_info("Extracting: Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS layers")
        self.console.print()

    def print_parsing_complete(self, packets: int, bytes_total: int, duration: float, flows: int) -> None:
        """Print parsing completion summary."""
        self.console.print()
        self.print_success(f"Parsing complete!")
        
        # Create summary table
        table = Table(box=None, show_header=False, padding=(0, 2))
        table.add_column("Label", style="dim")
        table.add_column("Value", style="bright_white")
        
        table.add_row("Total Packets", f"{packets:,}")
        table.add_row("Total Bytes", self._format_bytes(bytes_total))
        table.add_row("Duration", self._format_duration(duration))
        table.add_row("Unique Flows", f"{flows:,}")
        
        self.console.print(table)

    # =========================================================================
    # Statistics Display
    # =========================================================================

    def print_statistics_start(self) -> None:
        """Print statistics phase start."""
        self.print_phase_header(
            "statistics",
            "PHASE 2: Computing Statistics",
            "Analyzing traffic patterns, protocol distribution, and network behavior"
        )
        self.print_info("Computing protocol distribution across all layers")
        self.print_info("Identifying top talkers (source/destination IPs and ports)")
        self.print_info("Building traffic timeline with 60-second buckets")
        self.print_info("Calculating payload entropy for encrypted content detection")

    def print_statistics(self, stats: dict) -> None:
        """Print detailed statistics."""
        self.console.print()
        
        # Traffic Overview
        self.console.print("[bold bright_white]📈 Traffic Overview[/bold bright_white]")
        overview_table = Table(box=ROUNDED, border_style="dim")
        overview_table.add_column("Metric", style="cyan")
        overview_table.add_column("Value", style="bright_white", justify="right")
        
        summary = stats.get("summary", stats)
        overview_table.add_row("Total Packets", f"{summary.get('total_packets', 0):,}")
        overview_table.add_row("Total Bytes", self._format_bytes(summary.get('total_bytes', 0)))
        overview_table.add_row("Duration", self._format_duration(summary.get('duration_seconds', 0)))
        overview_table.add_row("Unique IPs", f"{summary.get('unique_ips', 0):,}")
        overview_table.add_row("Total Flows", f"{summary.get('total_flows', 0):,}")
        
        self.console.print(overview_table)
        self.console.print()

        # Protocol Distribution
        protocol_stats = stats.get("protocol_stats", {})
        if protocol_stats:
            self.console.print("[bold bright_white]🔌 Protocol Distribution[/bold bright_white]")
            proto_table = Table(box=ROUNDED, border_style="dim")
            proto_table.add_column("Protocol", style="cyan")
            proto_table.add_column("Packets", style="bright_white", justify="right")
            proto_table.add_column("Percentage", style="bright_green", justify="right")
            
            transport = protocol_stats.get("transport_protocols", {})
            transport_pct = protocol_stats.get("transport_percentages", {})
            for proto, count in sorted(transport.items(), key=lambda x: x[1], reverse=True)[:10]:
                pct = transport_pct.get(proto, 0)
                proto_table.add_row(proto.upper(), f"{count:,}", f"{pct:.1f}%")
            
            self.console.print(proto_table)
            self.console.print()

        # Top Talkers
        top_src = stats.get("top_src_ips", [])
        if top_src:
            self.console.print("[bold bright_white]🔝 Top Source IPs[/bold bright_white]")
            src_table = Table(box=ROUNDED, border_style="dim")
            src_table.add_column("IP Address", style="bright_yellow")
            src_table.add_column("Packets", style="bright_white", justify="right")
            src_table.add_column("Bytes", style="bright_green", justify="right")
            
            for item in top_src[:10]:
                ip = item.get("identifier", item.get("ip", ""))
                packets = item.get("packet_count", 0)
                bytes_count = item.get("byte_count", 0)
                src_table.add_row(ip, f"{packets:,}", self._format_bytes(bytes_count))
            
            self.console.print(src_table)
            self.console.print()

        top_dst = stats.get("top_dst_ips", [])
        if top_dst:
            self.console.print("[bold bright_white]🎯 Top Destination IPs[/bold bright_white]")
            dst_table = Table(box=ROUNDED, border_style="dim")
            dst_table.add_column("IP Address", style="bright_yellow")
            dst_table.add_column("Packets", style="bright_white", justify="right")
            dst_table.add_column("Bytes", style="bright_green", justify="right")
            
            for item in top_dst[:10]:
                ip = item.get("identifier", item.get("ip", ""))
                packets = item.get("packet_count", 0)
                bytes_count = item.get("byte_count", 0)
                dst_table.add_row(ip, f"{packets:,}", self._format_bytes(bytes_count))
            
            self.console.print(dst_table)
            self.console.print()

    # =========================================================================
    # Detection Results
    # =========================================================================

    def print_detection_start(self) -> None:
        """Print detection phase start."""
        self.print_phase_header(
            "detection",
            "PHASE 3: Running Detection Engines",
            "Analyzing traffic for malicious patterns and anomalies"
        )
        self.print_info("Beacon Detector: Looking for periodic callback patterns (C2 beacons)")
        self.print_info("DNS Tunnel Detector: Analyzing DNS queries for data exfiltration")
        self.print_info("Exfiltration Detector: Checking outbound data transfer ratios")
        self.print_info("Port Scan Detector: Identifying reconnaissance activity")

    def print_detector_result(self, detector: str, findings_count: int) -> None:
        """Print individual detector result."""
        if findings_count > 0:
            self.print_warning(f"{detector}: Found {findings_count} suspicious pattern(s)")
        else:
            self.print_success(f"{detector}: No suspicious patterns detected")

    def print_findings(self, findings: list[dict]) -> None:
        """Print detection findings."""
        if not findings:
            self.console.print()
            self.print_success("No security threats detected!")
            return

        self.console.print()
        self.console.print(f"[bold bright_red]⚠ Found {len(findings)} Security Finding(s)[/bold bright_red]")
        self.console.print()

        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "medium")
            color = SEVERITY_COLORS.get(severity, "white")
            
            # Finding header
            self.console.print(
                f"[{color}]━━━ Finding #{i}: {finding.get('title', 'Unknown')} ━━━[/{color}]"
            )
            
            # Finding details table
            table = Table(box=None, show_header=False, padding=(0, 2))
            table.add_column("Field", style="dim", width=15)
            table.add_column("Value", style="bright_white")
            
            table.add_row("Severity", f"[{color}]{severity.upper()}[/{color}]")
            table.add_row("Detector", finding.get("detector", "Unknown"))
            table.add_row("Confidence", f"{finding.get('confidence', 0) * 100:.0f}%")
            
            if finding.get("description"):
                table.add_row("Description", finding["description"][:100])
            
            affected_ips = finding.get("affected_ips", [])
            if affected_ips:
                table.add_row("Affected IPs", ", ".join(affected_ips[:5]))
            
            self.console.print(table)
            self.console.print()

    # =========================================================================
    # Cascading Enrichment Results
    # =========================================================================

    def print_cascading_enrichment_start(self, total_ips: int, total_domains: int) -> None:
        """Print cascading enrichment phase start."""
        self.print_phase_header(
            "enrichment",
            "PHASE 4: Cascading Threat Intelligence Enrichment",
            "Step 1: AlienVault OTX → Step 2: AbuseIPDB → Step 3: VirusTotal"
        )
        self.print_info(f"Found {total_ips} unique non-private IPs and {total_domains} domains to analyze")
        self.console.print()

    def print_enrichment_step_start(self, step: str, description: str, limit: str) -> None:
        """Print the start of an enrichment step."""
        self.console.print(f"─── [bold cyan]Step {step}[/bold cyan] [dim]({limit})[/dim] ───")
        self.console.print(f"  [dim]{description}[/dim]")

    def print_enrichment_progress(
        self,
        step: str,
        current: int,
        total: int,
        indicator: str,
        is_flagged: bool,
        threat_level: str,
        details: str = "",
    ) -> None:
        """Print enrichment progress for a single indicator."""
        # Truncate indicator if too long
        max_len = 30
        display_indicator = indicator if len(indicator) <= max_len else indicator[:max_len-3] + "..."
        
        # Determine status symbol and color
        if threat_level == "malicious":
            status = "[red bold]🔴 MALICIOUS[/red bold]"
        elif threat_level == "suspicious" or is_flagged:
            status = "[yellow]⚠ flagged[/yellow]"
        else:
            status = "[green]✓ clean[/green]"
        
        # Build the line
        line = f"  [{current:3}/{total}] {display_indicator:32} {status}"
        if details and threat_level in ("malicious", "suspicious"):
            line += f" [dim]({details})[/dim]"
        
        self.console.print(line)

    def print_enrichment_step_complete(self, step: str, checked: int, flagged: int) -> None:
        """Print enrichment step completion summary."""
        self.console.print()
        self.console.print(f"  [green]✓[/green] {step} complete: {checked} checked, {flagged} flagged")
        self.console.print()

    def print_flagged_indicators(self, flagged_indicators: list) -> None:
        """Print the table of flagged indicators with red highlighting."""
        if not flagged_indicators:
            self.console.print()
            self.console.print("[green]✅ No malicious indicators found in threat intelligence databases.[/green]")
            return

        self.console.print()
        self.console.print(Panel(
            "[bold red]🚨 FLAGGED INDICATORS (Malicious/Suspicious)[/bold red]",
            border_style="red",
            padding=(0, 1),
        ))
        self.console.print()

        for item in flagged_indicators[:25]:
            indicator = item.get("indicator", "")
            threat_level = item.get("threat_level", "unknown")
            summary = item.get("summary", "")
            malware_families = item.get("malware_families", [])
            
            # Color based on threat level
            if threat_level == "malicious":
                emoji = "🔴"
                color = "red bold"
            else:
                emoji = "⚠"
                color = "yellow"
            
            # Build the line
            line = f"  {emoji} [{color}]{indicator:35}[/{color}] {summary}"
            if malware_families:
                line += f" [bright_magenta]({', '.join(malware_families[:3])})[/bright_magenta]"
            
            self.console.print(line)

    def print_enrichment_stats(self, stats: dict) -> None:
        """Print enrichment statistics table."""
        self.console.print()
        self.console.print("[bold bright_white]📊 Enrichment Statistics[/bold bright_white]")
        
        table = Table(box=ROUNDED, border_style="dim")
        table.add_column("Source", style="cyan")
        table.add_column("Checked", style="bright_white", justify="right")
        table.add_column("Flagged", style="yellow", justify="right")
        table.add_column("Errors", style="red", justify="right")
        
        if "otx" in stats:
            otx = stats["otx"]
            table.add_row(
                "AlienVault OTX",
                str(otx.get("checked", 0)),
                str(otx.get("flagged", 0)),
                str(otx.get("errors", 0)),
            )
        
        if "abuseipdb" in stats:
            abuse = stats["abuseipdb"]
            table.add_row(
                "AbuseIPDB",
                str(abuse.get("checked", 0)),
                str(abuse.get("flagged", 0)),
                str(abuse.get("errors", 0)),
            )
        
        if "virustotal" in stats:
            vt = stats["virustotal"]
            table.add_row(
                "VirusTotal",
                str(vt.get("checked", 0)),
                str(vt.get("malicious", 0)),
                str(vt.get("errors", 0)),
            )
        
        self.console.print(table)

    # Legacy methods for backward compatibility
    def print_enrichment_start(self) -> None:
        """Print enrichment phase start (legacy)."""
        self.print_phase_header(
            "enrichment",
            "PHASE 4: Threat Intelligence Enrichment",
            "Querying external reputation databases for flagged indicators"
        )

    def print_enrichment_skipped(self, reason: str) -> None:
        """Print enrichment skipped message."""
        self.print_warning(f"Enrichment skipped: {reason}")

    def print_enrichment_results(self, enrichment: dict) -> None:
        """Print enrichment results (legacy format)."""
        if not enrichment:
            return

        stats = enrichment.get("stats", {})
        
        # Handle new cascading stats format
        if "otx" in stats or "abuseipdb" in stats or "virustotal" in stats:
            self.print_enrichment_stats(stats)
            
            flagged = enrichment.get("flagged_indicators", [])
            self.print_flagged_indicators(flagged)
        else:
            # Old format
            results = enrichment.get("results", [])
            
            self.console.print()
            self.console.print("[bold bright_white]🌐 Enrichment Summary[/bold bright_white]")
            
            summary_table = Table(box=ROUNDED, border_style="dim")
            summary_table.add_column("Metric", style="cyan")
            summary_table.add_column("Count", style="bright_white", justify="right")
            
            summary_table.add_row("Total Indicators Checked", str(stats.get("total_indicators", 0)))
            summary_table.add_row("Malicious Found", f"[red]{stats.get('malicious_found', 0)}[/red]")
            summary_table.add_row("Suspicious Found", f"[yellow]{stats.get('suspicious_found', 0)}[/yellow]")
            
            self.console.print(summary_table)

            # Show malicious indicators
            malicious = [r for r in results if r.get("verdict") == "malicious"]
            if malicious:
                self.console.print()
                self.console.print("[bold red]🚨 Malicious Indicators[/bold red]")
                
                for item in malicious[:10]:
                    indicator = item.get("indicator", "")
                    sources = item.get("sources", [])
                    self.console.print(f"  [red]•[/red] {indicator} [dim](from: {', '.join(sources)})[/dim]")

    # =========================================================================
    # Report Save Prompt
    # =========================================================================

    def prompt_save_report(self) -> bool:
        """Prompt user to save report."""
        self.console.print()
        response = self.console.input("[bold bright_white]Save analysis report? [Y/n]:[/bold bright_white] ")
        return response.lower() != "n"

    def print_report_saved(self, path: str) -> None:
        """Print report saved confirmation."""
        self.console.print(f"  [green]✓[/green] Report saved to: [bright_cyan]{path}[/bright_cyan]")

    # =========================================================================
    # AI Analysis Results
    # =========================================================================

    def print_ai_analysis_start(self) -> None:
        """Print AI analysis phase start."""
        self.print_phase_header(
            "ai_analysis",
            "PHASE 5: AI-Powered Analysis",
            "Using LLMs to interpret findings and identify complex attack patterns"
        )
        self.print_info("Stats Model: deepseek/deepseek-r1-0528:free (reasoning model)")
        self.print_info("Detection Model: tngtech/deepseek-r1t-chimera:free (behavioral analysis)")
        self.print_info("Synthesis Model: deepseek/deepseek-r1-0528:free (final correlation)")

    def print_ai_skipped(self, reason: str) -> None:
        """Print AI analysis skipped message."""
        self.print_warning(f"AI analysis skipped: {reason}")

    def print_ai_insights(self, insights: dict) -> None:
        """Print AI insights."""
        if not insights or insights.get("status") != "success":
            return

        self.console.print()
        self.console.print("[bold bright_white]🤖 AI Statistical Analysis[/bold bright_white]")
        
        content = insights.get("content", "")
        if content:
            # Wrap in a panel for readability
            self.console.print(Panel(
                Markdown(content[:2000]),  # Limit length
                border_style="bright_blue",
                padding=(1, 2),
            ))

    def print_synthesis(self, synthesis: dict) -> None:
        """Print synthesis results."""
        if not synthesis or not synthesis.get("success"):
            return

        self.print_phase_header(
            "synthesis",
            "PHASE 6: Final Synthesis",
            "Correlating all findings into actionable intelligence"
        )

        # Threat level
        threat_level = synthesis.get("threat_level", "unknown")
        threat_colors = {
            "critical": "red bold",
            "high": "bright_red",
            "medium": "yellow",
            "low": "green",
            "none": "bright_green",
        }
        threat_color = threat_colors.get(threat_level, "white")
        
        self.console.print(f"[bold]Threat Level:[/bold] [{threat_color}]{threat_level.upper()}[/{threat_color}]")
        self.console.print()

        # Executive summary
        summary = synthesis.get("executive_summary", "")
        if summary:
            self.console.print("[bold bright_white]📋 Executive Summary[/bold bright_white]")
            self.console.print(Panel(summary, border_style="dim", padding=(1, 2)))

        # Key findings
        key_findings = synthesis.get("key_findings", [])
        if key_findings:
            self.console.print()
            self.console.print("[bold bright_white]🔑 Key Findings[/bold bright_white]")
            for finding in key_findings[:5]:
                self.console.print(f"  • {finding}")

        # Recommendations
        recommendations = synthesis.get("recommendations", [])
        if recommendations:
            self.console.print()
            self.console.print("[bold bright_white]💡 Recommendations[/bold bright_white]")
            for rec in recommendations[:5]:
                self.console.print(f"  • {rec}")

    # =========================================================================
    # Wireshark Filters
    # =========================================================================

    def print_wireshark_filters(self, filters: list[dict]) -> None:
        """Print Wireshark filters."""
        if not filters:
            return

        self.print_phase_header(
            "filters",
            "PHASE 7: Wireshark Filters Generated",
            "Copy these filters into Wireshark for manual investigation"
        )

        for i, f in enumerate(filters[:20], 1):
            name = f.get("name", f"Filter {i}")
            filter_text = f.get("filter_text", f.get("filter", ""))
            severity = f.get("severity", "medium")
            color = SEVERITY_COLORS.get(severity, "white")
            
            self.console.print(f"[{color}]#{i}[/{color}] [bold]{name}[/bold]")
            if f.get("description"):
                self.console.print(f"   [dim]{f['description'][:80]}[/dim]")
            self.console.print(f"   [bright_cyan]{filter_text}[/bright_cyan]")
            self.console.print()

    # =========================================================================
    # Completion
    # =========================================================================

    def print_analysis_complete(self, elapsed: float, summary: dict) -> None:
        """Print analysis completion summary."""
        self.console.print()
        self.console.print(f"{'═' * self._width}", style="bright_green")
        self.console.print(" ✅ [bold bright_green]ANALYSIS COMPLETE[/bold bright_green]")
        self.console.print(f"{'═' * self._width}", style="bright_green")
        self.console.print()

        # Final summary table
        table = Table(
            title="Analysis Summary",
            box=DOUBLE,
            border_style="bright_green",
            title_style="bold bright_white",
        )
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bright_white", justify="right")

        table.add_row("Total Time", self._format_duration(elapsed))
        table.add_row("Packets Analyzed", f"{summary.get('total_packets', 0):,}")
        table.add_row("Total Bytes", self._format_bytes(summary.get('total_bytes', 0)))
        table.add_row("Detections", str(summary.get('detections', 0)))
        table.add_row("Enriched Indicators", str(summary.get('enriched_indicators', 0)))
        table.add_row("Malicious Indicators", str(summary.get('malicious_indicators', 0)))
        table.add_row("Threat Level", summary.get('threat_level', 'unknown').upper())
        table.add_row("Wireshark Filters", str(len(summary.get('wireshark_filters', []))))

        self.console.print(table)
        self.console.print()
        self.console.print("[dim]Scroll up to review detailed output for each analysis phase.[/dim]")

    def print_analysis_error(self, error: str) -> None:
        """Print analysis error."""
        self.console.print()
        self.console.print(f"{'═' * self._width}", style="red")
        self.console.print(f" {PHASE_ICONS['error']} [bold red]ANALYSIS FAILED[/bold red]")
        self.console.print(f"{'═' * self._width}", style="red")
        self.console.print()
        self.console.print(f"[red]{error}[/red]")

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes to human readable string."""
        if bytes_count < 1024:
            return f"{bytes_count} B"
        elif bytes_count < 1024 ** 2:
            return f"{bytes_count / 1024:.1f} KB"
        elif bytes_count < 1024 ** 3:
            return f"{bytes_count / (1024 ** 2):.1f} MB"
        else:
            return f"{bytes_count / (1024 ** 3):.2f} GB"

    def _format_duration(self, seconds: float) -> str:
        """Format duration to human readable string."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"


# =============================================================================
# Singleton Instance
# =============================================================================

_console: NetSpecterConsole | None = None


def get_console() -> NetSpecterConsole:
    """Get the singleton console instance."""
    global _console
    if _console is None:
        _console = NetSpecterConsole()
    return _console
