"""CLI entrypoint for IOC Triage."""

import argparse
import asyncio
import json
from pathlib import Path
from typing import List

from dotenv import load_dotenv
import httpx
from rich.console import Console
from rich.table import Table

from src.client import ThreatIntelClient, TriageReport
from src.validator import classify_indicator, is_routable_ip

load_dotenv()
console = Console()


async def triage_indicator(
    client: ThreatIntelClient, http_client: httpx.AsyncClient, indicator: str
) -> TriageReport:
    """Orchestrates multi-source lookups for a single indicator."""
    ind_type = classify_indicator(indicator)
    report = TriageReport(indicator=indicator, indicator_type=ind_type, errors=[])

    if ind_type == "unknown":
        report.errors.append("Invalid or unsupported indicator format")
        return report

    if ind_type == "ipv4":
        if not is_routable_ip(indicator):
            report.errors.append("Private/non-routable IP skipped")
            return report

        vt_task = client.query_virustotal_ip(http_client, indicator)
        abuse_task = client.query_abuseipdb(http_client, indicator)
        vt_res, abuse_res = await asyncio.gather(vt_task, abuse_task)
        report.virustotal = vt_res
        report.abuseipdb = abuse_res

    elif ind_type.startswith("hash_"):
        report.virustotal = await client.query_virustotal_hash(http_client, indicator)

    return report


def render_report_table(reports: List[TriageReport]) -> None:
    """Renders formatted results using Rich."""
    table = Table(title="IOC Triage Summary", show_header=True, header_style="bold cyan")
    table.add_column("Indicator", style="bold white")
    table.add_column("Type", style="dim")
    table.add_column("VT Score", justify="center")
    table.add_column("AbuseIPDB Score", justify="center")
    table.add_column("Context / Details")

    for rep in reports:
        if rep.errors:
            table.add_row(rep.indicator, rep.indicator_type, "-", "-", f"[red]{', '.join(rep.errors)}[/red]")
            continue

        vt_score = "N/A"
        if rep.virustotal and "malicious" in rep.virustotal:
            mal = rep.virustotal["malicious"]
            color = "red" if mal > 3 else "yellow" if mal > 0 else "green"
            vt_score = f"[{color}]{mal} detections[/{color}]"
        elif rep.virustotal and "error" in rep.virustotal:
            vt_score = "[yellow]Error[/yellow]"

        abuse_score = "N/A"
        if rep.abuseipdb and "abuse_score" in rep.abuseipdb:
            score = rep.abuseipdb["abuse_score"]
            color = "red" if score >= 50 else "yellow" if score > 0 else "green"
            abuse_score = f"[{color}]{score}%[/{color}]"
        elif rep.abuseipdb and "error" in rep.abuseipdb:
            abuse_score = "[yellow]Error[/yellow]"

        context = []
        if rep.abuseipdb and "isp" in rep.abuseipdb:
            context.append(f"ISP: {rep.abuseipdb['isp']} ({rep.abuseipdb.get('country')})")
        if rep.virustotal and "meaningful_name" in rep.virustotal:
            context.append(f"File: {rep.virustotal['meaningful_name']}")

        details = " | ".join(context) if context else "None"
        table.add_row(rep.indicator, rep.indicator_type, vt_score, abuse_score, details)

    console.print(table)


async def main_async() -> None:
    parser = argparse.ArgumentParser(description="Async SOC IOC Triage & Enrichment CLI")
    parser.add_argument("-i", "--indicator", type=str, help="Single IP address or file hash")
    parser.add_argument("-f", "--file", type=Path, help="Text file with one IOC per line")
    parser.add_argument("-o", "--output", type=Path, help="Export output as JSON file")

    args = parser.parse_args()
    indicators: List[str] = []

    if args.indicator:
        indicators.append(args.indicator.strip())
    elif args.file:
        if not args.file.exists():
            console.print(f"[red]Error:[/red] File {args.file} not found.")
            return
        indicators = [line.strip() for line in args.file.read_text().splitlines() if line.strip()]
    else:
        parser.print_help()
        return

    client = ThreatIntelClient()
    async with httpx.AsyncClient() as http_client:
        tasks = [triage_indicator(client, http_client, ind) for ind in indicators]
        reports = await asyncio.gather(*tasks)

    render_report_table(reports)

    if args.output:
        data = [rep.__dict__ for rep in reports]
        args.output.write_text(json.dumps(data, indent=2))
        console.print(f"\n[green]Results successfully exported to {args.output}[/green]")


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
