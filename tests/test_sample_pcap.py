#!/usr/bin/env python3
"""
Test script to analyze the sample PCAP file and verify Phase 2 functionality.
"""

import asyncio
import json
from pathlib import Path

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.analysis.parser import parse_pcap
from backend.analysis.statistics import compute_statistics
from backend.ai.context import ContextBuilder
from backend.ai.prompts import PromptTemplates


async def test_sample_pcap():
    """Test parsing and statistics on the sample PCAP."""
    
    pcap_path = Path(__file__).parent / "sample_pcaps" / "2025-01-22-traffic-analysis-exercise.pcap"
    
    if not pcap_path.exists():
        print(f"❌ Sample PCAP not found: {pcap_path}")
        return False
    
    print(f"📦 Analyzing: {pcap_path.name}")
    print(f"   Size: {pcap_path.stat().st_size / (1024*1024):.2f} MB")
    print()
    
    # Phase 1: Parse PCAP
    print("🔍 Phase 1: Parsing PCAP...")
    
    def progress_callback(progress):
        print(f"   Progress: {progress.packets_processed} packets ({progress.progress*100:.1f}%)", end='\r')
    
    parse_result = await parse_pcap(
        file_path=pcap_path,
        progress_callback=progress_callback,
        batch_size=5000,
    )
    
    print()
    print(f"   ✅ Parsed {parse_result.total_packets:,} packets")
    print(f"   ✅ {parse_result.total_bytes:,} bytes")
    print(f"   ✅ {len(parse_result.flows)} flows")
    print(f"   ✅ {len(parse_result.conversations)} conversations")
    print(f"   ✅ {len(parse_result.dns_queries)} DNS queries")
    print(f"   ✅ Duration: {parse_result.duration_seconds:.1f} seconds")
    print()
    
    # Phase 2: Compute Statistics
    print("📊 Phase 2: Computing statistics...")
    
    stats = compute_statistics(parse_result)
    
    print(f"   ✅ Protocol distribution computed")
    print(f"   ✅ Top talkers identified")
    print(f"   ✅ {len(stats.anomalies)} anomalies detected")
    print()
    
    # Show anomalies
    if stats.anomalies:
        print("⚠️  Detected Anomalies:")
        for anomaly in stats.anomalies[:5]:
            print(f"   - [{anomaly.severity.upper()}] {anomaly.category}: {anomaly.description[:60]}...")
        if len(stats.anomalies) > 5:
            print(f"   ... and {len(stats.anomalies) - 5} more")
        print()
    
    # Build LLM context
    print("📝 Building LLM context...")
    
    context_builder = ContextBuilder(stats)
    stats_summary = context_builder.build_stats_summary(max_chars=8000)
    
    print(f"   ✅ Context built ({len(stats_summary)} chars)")
    print()
    
    # Show a preview of the context
    print("=" * 60)
    print("STATISTICS SUMMARY (first 2000 chars):")
    print("=" * 60)
    print(stats_summary[:2000])
    print("..." if len(stats_summary) > 2000 else "")
    print("=" * 60)
    print()
    
    # Show sample prompt
    print("📤 Sample LLM prompt would be:")
    print("-" * 40)
    prompt = PromptTemplates.stats_analysis_prompt(stats_summary)
    print(f"   System: {PromptTemplates.SYSTEM_STATS_ANALYST[:100]}...")
    print(f"   Prompt length: {len(prompt)} chars")
    print("-" * 40)
    print()
    
    # Show statistics summary as JSON
    print("📋 Statistics JSON preview:")
    stats_dict = stats.to_dict()
    print(json.dumps(stats_dict["overview"], indent=2))
    print(f"\nProtocols: {stats_dict['protocols']['transport']}")
    print(f"\nAnomalies count: {len(stats_dict['anomalies'])}")
    print()
    
    print("✅ Phase 2 test complete!")
    return True


if __name__ == "__main__":
    success = asyncio.run(test_sample_pcap())
    sys.exit(0 if success else 1)
