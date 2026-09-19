import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from constants import ByteUnits, ProtocolColors, TimeConstants
from models import CaptureStats, PacketInfo, Protocol

def get_console() -> Console:
    """
    create console with env-aware settings
    """
    if not sys.stdout.isatty():
        return Console(force_terminal=False, no_color=True)
    if os.environ.get("CI"):
        return Console(force_terminal=True, force_interactive=False)
    if os.environ.get("NO_COLOR"):
        return Console(no_color=True)
    return Console()

console = get_console()

def create_capture_progress() -> Progress:
    """
    create progress display for packet capture
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True
    )

def _get_protocol_color(prot: Protocol) -> str:
    """
    get Rich color for a protocol
    """
    return ProtocolColors.RICH.get(prot.value, "white")

def print_packet(packet: PacketInfo) -> None:
    """
    print single packet info
    """
    color = _get_protocol_color(packet.protocol)
    port_info = ""

    if packet.src_port and packet.dest_port:
        port_info = f":{packet.src_port} -> :{packet.dest_port}"

    console.print(
        f"[{color}]{packet.protocol.value:5}[/{color}] "
        f"{packet.src_ip:15} -> {packet.dest_ip:15} "
        f"{port_info:20} "
        f"[dim]{packet.size:6} bytes[/dim]"
    )

def print_protocol_table(stats: CaptureStats) -> None:
    """
    print protocol distribution table
    """
    table = Table(title="Protocol Distribution")
    table.add_column("Protocol", style="cyan", justify="left")
    table.add_column("Packets", style="green", justify="right")
    table.add_column("Bytes", style="yellow", justify="right")
    table.add_column("Percentage", style="magenta", justify="right")

    percentages = stats.get_prot_distribution()

    for protocol in sorted(stats.prot_distribution.keys(), key=lambda p: p.value):
        count = stats.prot_distribution[protocol]
        bytes_count = stats.prot_bytes.get(protocol, 0)
        pct = percentages.get(protocol, 0.0)
        table.add_row(
            protocol.value,
            f"{count:,}",
            format_bytes(bytes_count),
            f"{pct:.1f}%"
        )
    
    console.print(table)

def print_top_talkers(stats: CaptureStats, limit: int = 10) -> None:
    """
    print top talkers table
    """
    table = Table(title=f"Top {limit} Talkers")
    table.add_column("IP Address", style="cyan", justify="left")
    table.add_column("Packets Sent", style="green", justify="right")
    table.add_column("Packets Recv", style="yellow", justify="right")
    table.add_column("Bytes Sent", style="blue", justify="right")
    table.add_column("Bytes Recv", style="magenta", justify="right")
    table.add_column("Total", style="white", justify="right")

    top_talkers = stats.get_top_hosts(limit)

    for host in top_talkers:
        table.add_row(
            host.ip_addr,
            f"{host.packets_sent:,}",
            f"{host.packets_recv:,}",
            format_bytes(host.bytes_sent),
            format_bytes(host.bytes_recv),
            format_bytes(host.tot_bytes)
        )

    console.print(table)

def print_capture_summary(stats: CaptureStats) -> None:
    """
    print capture session summary panel
    """
    duration = stats.capture_time
    avg_bandwidth = stats.bandwidth_avg

    summary_lines = [
        f"Duration: {format_duration(duration)}",
        f"Total Packets: {stats.packets_tot:,}",
        f"Total Bytes: {format_bytes(stats.bytes_tot)}",
        f"Average Bandwidth: {format_bytes(avg_bandwidth)}/s",
        f"Unique Endpoints: {len(stats.hosts)}",
        f"Protocols Seen: {len(stats.prot_distribution)}"
    ]

    panel = Panel(
        "\n".join(summary_lines),
        title="[bold]Capture Summary[/bold]",
        border_style="green",
    )
    console.print(panel)

def print_bandwidth_stats(stats: CaptureStats) -> None:
    """
    print bandwidth stats
    """
    if not stats.bandwidth_samples:
        console.print("[yellow]No bandwidth samples recorded[/yellow]")
        return
    
    samples = stats.bandwidth_samples
    max_bps = max(s.bytes_per_sec for s in samples)
    min_bps = min(s.bytes_per_sec for s in samples)
    avg_bps = sum(s.bytes_per_sec for s in samples) / len(samples)

    table = Table(title="Bandwidth Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green", justify="right")

    table.add_row("Peak", f"{format_bytes(max_bps)}/s")
    table.add_row("Minimum", f"{format_bytes(min_bps)}/s")
    table.add_row("Average", f"{format_bytes(avg_bps)}/s")
    table.add_row("Samples", f"{len(samples)}")

    console.print(table)

def print_interfaces(interfaces: list[str]) -> None:
    """
    print available network interfaces
    """
    table = Table(title="Available Interfaces")
    table.add_column("Interface", style="cyan")

    for iface in interfaces:
        table.add_row(iface)

    console.print(table)

def print_error(message: str) -> None:
    """
    print error message
    """
    console.print(f"[red]Error:[/red] {message}")

def print_warning(message: str) -> None:
    """
    print warning message
    """
    console.print(f"[yellow]Warning:[/yellow] {message}")

def print_success(message: str) -> None:
    """
    print success message
    """
    console.print(f"[green]Success:[/green] {message}")

def format_bytes(num_bytes: int | float) -> str:
    """
    format byte count with appropriate units
    """
    for unit in ByteUnits.UNITS[:-1]:
        if abs(num_bytes) < ByteUnits.BYTES_PER_KB:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= ByteUnits.BYTES_PER_KB
    return f"{num_bytes:.1f} {ByteUnits.UNITS[-1]}"

def format_duration(seconds: float) -> str:
    """
    format capture time in human-readable format
    """
    if seconds < TimeConstants.SEC_PER_MIN:
        return f"{seconds:.1f}s"
    if seconds < TimeConstants.SEC_PER_HR:
        minutes = int(seconds // TimeConstants.SEC_PER_MIN)
        secs = seconds % TimeConstants.SEC_PER_MIN
        return f"{minutes}m {secs:.1f}s"
    hours = int(seconds // TimeConstants.SEC_PER_HR)
    minutes = int(
        (seconds % TimeConstants.SEC_PER_HR) //
        TimeConstants.SEC_PER_MIN
    )
    return f"{hours}h {minutes}m"

__all__ = [
    "console",
    "create_capture_progress",
    "format_bytes",
    "format_duration",
    "get_console",
    "print_bandwidth_stats",
    "print_capture_summary",
    "print_error",
    "print_interfaces",
    "print_packet",
    "print_protocol_table",
    "print_success",
    "print_top_talkers",
    "print_warning",
]