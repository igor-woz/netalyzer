import json
from pathlib import Path
from typing import Annotated, Literal

import typer

from analyzer import analyze_pcap_file
from capture import (
    CaptureConfig,
    CaptureEngine,
    GracefulCapture,
    check_capture_permissions,
    get_available_interfaces
)
from export import (
    export_packets_csv,
    export_to_json,
    stats_to_dict
)
from filters import validate_bpf_filter
from models import CaptureStats, PacketInfo
from output import (
    console,
    print_bandwidth_stats,
    print_capture_summary,
    print_error,
    print_interfaces,
    print_packet,
    print_protocol_table,
    print_success,
    print_top_talkers,
    print_warning
)
from stats import StatsCollector
from visualization import (
    create_bandwidth_chart,
    create_protocol_bar_chart,
    create_top_hosts_chart,
    generate_all_charts,
    save_chart
)

ExportFormat = Literal["json", "csv"]
ChartType = Literal["protocols", "top-hosts", "bandwidth", "all"]

app = typer.Typer(
    name="netalyzer",
    help="[bold cyan]Network Traffic Analyzer[/bold cyan] - Capture and analyze packets",
    rich_markup_mode="rich",
    no_args_is_help=True
)

def _analyze_pcap_to_stats(pcap_file: Path) -> tuple[CaptureStats, list[PacketInfo]]:
    """
    analyze a pcap file and return statistics with packet list
    """
    packets = analyze_pcap_file(str(pcap_file))
    collector = StatsCollector()
    collector.start()

    for p in packets:
        collector.record_packet(p)

    return collector.get_stats(), packets

# TODO implement version_callback
def version_callback(value: bool) -> None:
    """
    display version and exit
    """

@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit",
            callback=version_callback,
            is_eager=True
        ),
    ] = None
) -> None:
    """
    Network Traffic Analyzer

    capture and analyze network packets with protocol distribution,
    top talkers identification, and bandwidth visualization.
    """

@app.command()
def capture(
    interface: Annotated[
        str | None,
        typer.Option(
            "--interface",
            "-i",
            help="Network interface to capture on"
        ),
    ] = None,
    filter_expr: Annotated[
        str | None,
        typer.Option(
            "--filter",
            "-f",
            help="BPF filter expression",
        ),
    ] = None,
    count: Annotated[
        int | None,
        typer.Option(
            "--count",
            "-c",
            help="Number of packets to capture",
        ),
    ] = None,
    timeout: Annotated[
        float | None,
        typer.Option(
            "--timeout",
            "-t",
            help="Capture timeout in seconds",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file for results (JSON)",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            help="Show individual packets",
        ),
    ] = False,
) -> None:
    """
    capture live network packets

    examples:
        netalyzer capture -i eth0 --count 100
        netalyzer capture --filter "tcp port 80" --timeout 30
        netalyzer capture -i lo -c 50 --verbose
    """
    can_capture, msg = check_capture_permissions()
    if not can_capture:
        print_error(f"cannot capture packets: {msg}")
        raise typer.Exit(1)
    
    if filter_expr and not validate_bpf_filter(filter_expr):
        print_error(f"invalid bpf filter: {filter_expr}")
        raise typer.Exit(1)
    
    config = CaptureConfig(
        interface=interface,
        bpf_filter=filter_expr,
        packet_count=count,
        timeout_seconds=timeout
    )

    packets_captured: list[PacketInfo] = []

    def on_packet(packet: PacketInfo) -> None:
        if verbose:
            print_packet(packet)
        if output:
            packets_captured.append(packet)

    console.print(
        f"[cyan]Starting capture on {interface or 'all interfaces'}...[/cyan]"
    )
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    engine = CaptureEngine(
        config=config,
        on_packet=on_packet if verbose or output else None
    )

    with GracefulCapture(engine) as cap:
        stats = cap.wait()

    console.print()
    print_capture_summary(stats)
    print_protocol_table(stats)
    print_top_talkers(stats)

    if output:
        export_to_json(stats, output, packets_captured)
        print_success(f"results saved to {output}")

@app.command()
def analyze(
    pcap_file: Annotated[
        Path,
        typer.Argument(help="pcap file to analyze")
    ],
    top_talkers: Annotated[
        int,
        typer.Option(
            "--top-talkers",
            "-t",
            help="show top N talkers"
        ),
    ] = 10,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="output results as json"
        ),
    ] = False
) -> None:
    """
    analyze packets from a pcap file

    examples:
        netalyzer analyze traffic.pcap
        netalyzer analyze traffic.pcap --top-talkers 20
        netalyzer analyze traffic.pcap --json
    """
    if not pcap_file.exists():
        print_error(f"file not found: {pcap_file}")
        raise typer.Exit(1)
    
    console.print(f"[cyan]analyzing {pcap_file}...[/cyan]")

    stats, _ = _analyze_pcap_to_stats(pcap_file)

    if json_output:
        console.print(json.dumps(stats_to_dict(stats), indent=2))
    else:
        print_capture_summary(stats)
        print_protocol_table(stats)
        print_top_talkers(stats, limit=top_talkers)

@app.command()
def stats(
    pcap_file: Annotated[
        Path,
        typer.Argument(help="pcap file to analyze")
    ],
    bandwidth: Annotated[
        bool,
        typer.Option(
            "--bandwidth",
            "-b",
            help="show bandwidth stats"
        ),  
    ] = False,
    protocols: Annotated[
        bool,
        typer.Option(
            "--protocol",
            "-p",
            help="show protocol distribution"
        ),
    ] = False,
    hosts: Annotated[
        bool,
        typer.Option(
            "--hosts",
            help="show host stats"
        ),
    ] = False,
) -> None:
    """
    display statistics from a pcap file

    examples:
        netalyzer stats traffic.pcap --bandwidth
        netalyzer stats traffic.pcap --protocols --endpoints
    """
    if not pcap_file.exists():
        print_error(f"file not found: {pcap_file}")
        raise typer.Exit(1)

    stats_result, _ = _analyze_pcap_to_stats(pcap_file)

    print_capture_summary(stats_result)

    if protocols or (not bandwidth and not hosts):
        print_protocol_table(stats_result)
    
    if hosts:
        print_top_talkers(stats_result, limit=20)

    if bandwidth:
        print_bandwidth_stats(stats_result)

@app.command("export")
def export_cmd(
    pcap_file: Annotated[
        Path,
        typer.Argument(help="pcap file to analyze")
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="output file path",
        ),
    ],
    format_type: Annotated[
        ExportFormat,
        typer.Option(
            "--format",
            "-f",
            help="output format",
        ),
    ] = "json",
) -> None:
    """
    capture data to csv or json

    examples:
        netalyzer export traffic.pcap -o results.json -f json
        netalyzer export traffic.pcap -o packets.csv -f csv
    """
    if not pcap_file.exists():
        print_error(f"file not found: {pcap_file}")
        raise typer.Exit(1)
    
    stats, packets = _analyze_pcap_to_stats(pcap_file)

    if format_type == "json":
        export_to_json(stats, output, packets)
    elif format_type == "csv":
        export_packets_csv(stats, output, packets)

    print_success(f"exported to {output}")

@app.command()
def chart(
    pcap_file: Annotated[
        Path,
        typer.Argument(help="pcap file to visualize"),
    ],
    chart_type: Annotated[
        ChartType,
        typer.Option(
            "--type",
            "-t",
            help="chart type",
        ),
    ] = "all",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="output file path (for single chart)",
        ),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output-dir",
            "-d",
            help="output directory (for all charts)",
        ),
    ] = None,
) -> None:
    """
    generate charts from capture data

    examples:
        netanal chart traffic.pcap --type protocols -o protocols.png
        netanal chart traffic.pcap --type all -d ./charts/
    """
    if not pcap_file.exists():
        print_error(f"file not found: {pcap_file}")
        raise typer.Exit(1)
    
    stats, _ = _analyze_pcap_to_stats(pcap_file)

    if chart_type == "all":
        out_dir = output_dir or Path()
        generated = generate_all_charts(stats, out_dir)
        for path in generated:
            print_success(f"generated {path}")
    else: 
        if not output:
            output = Path(f"{chart_type}.png")

        if chart_type == "protocols":
            fig = create_protocol_bar_chart(stats)
        elif chart_type == "top-hosts":
            fig = create_top_hosts_chart(stats)
        else:
            fig = create_bandwidth_chart(stats)

        save_chart(fig, output)
        print_success(f"generated {output}")

@app.command()
def interfaces() -> None:
    """
    list all available network interfaces
    """
    ifaces = get_available_interfaces()
    if not ifaces:
        print_warning("no interfaces found")
        raise typer.Exit(0)
    
    print_interfaces(ifaces)

if __name__ == "__main__":
    app()