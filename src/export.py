import csv
import json
from pathlib import Path
from typing import Any

from models import (
    CaptureStats,
    ExportOpts,
    PacketInfo,
    Protocol
)

def stats_to_dict(stats: CaptureStats) -> dict[str, Any]:
    """
    convert CaptureStats to json-serializable dictionary
    """
    prot_dist = {
        prot.value: count
        for prot, count in stats.prot_distribution.items()
    }

    prot_bytes = {
        prot.value: count
        for prot, count in stats.prot_bytes.items()
    }

    hosts = [
    {
        "ip_addr": h.ip_addr,
        "packets_sent": h.packets_sent,
        "packets_recv": h.packets_recv,
        "bytes_sent": h.bytes_sent,
        "bytes_recv": h.bytes_recv,
        "tot_bytes": h.tot_bytes,
    } for h in stats.hosts.values()
    ]

    convos = [
        {
            "host_1": c.host_1,
            "host_2": c.host_2,
            "packets_tot": c.packets_tot,
            "bytes_tot": c.bytes_tot
        } for c in stats.convo.values()
    ]

    bandwidth_samples = [
        {
            "timestamp": s.timestamp,
            "packets_per_sec": s.packets_per_sec,
            "bytes_per_sec": s.bytes_per_sec
        } for s in stats.bandwidth_samples
    ]

    return {
        "t_start": stats.t_start,
        "t_end": stats.t_end,
        "capture_time": stats.capture_time,
        "packets_tot": stats.packets_tot,
        "bytes_tot": stats.bytes_tot,
        "bandwidth_avg": stats.bandwidth_avg,
        "prot_dist": prot_dist,
        "protocol_bytes": prot_bytes,
        "hosts": hosts,
        "conversations": convos,
        "bandwidth_samples": bandwidth_samples
    }

def packet_to_dict(packet: PacketInfo) -> dict[str, Any]:
    """
    convert PacketInfo to json-serializable dictionary
    """
    return {
        "timestamp": packet.timestamp,
        "src_ip": packet.src_ip,
        "dest_ip": packet.dest_ip,
        "protocol": packet.protocol.value,
        "size": packet.size,
        "src_port": packet.src_port,
        "dest_port": packet.dest_port,
        "src_mac": packet.src_mac,
        "dest_mac": packet.dest_mac
    }

def export_to_json(
        stats: CaptureStats,
        filepath: Path,
        packets: list[PacketInfo] | None = None,
        options: ExportOpts | None = None
) -> None:
    """
    export capture data json file
    """
    if options is None:
        options = ExportOpts()

    data: dict[str, Any] = {}

    if options.include_stats:
        stats_dict = stats_to_dict(stats)
        if not options.include_hosts:
            stats_dict.pop("hosts", None)
        if not options.include_convos:
            stats_dict.pop("conversations", None)
        data["statistics"] = stats_dict

    if options.include_packets and packets:
        data["packets"] = [packet_to_dict(p) for p in packets]

    indent = 2 if options.pretty_print else None

    with filepath.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)

def export_packets_csv(
        stats: CaptureStats,
        filepath: Path,
        packets: list[PacketInfo] | None = None
) -> None:
    """
    export packet data to csv file
    """
    fieldnames = [
        "timestamp",
        "src_ip",
        "dest_ip",
        "protocol",
        "size",
        "src_port",
        "dest_port",
        "src_mac",
        "dest_mac",
    ]
    
    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        if packets:
            for packet in packets:
                writer.writerow(packet_to_dict(packet))

def export_hosts_csv(stats: CaptureStats, filepath: Path) -> None:
    """
    export endpoint stats to csv file
    """
    fieldnames = [
        "ip_address",
        "packets_sent",
        "packets_received",
        "bytes_sent",
        "bytes_received",
        "total_packets",
        "total_bytes",
    ]

    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for host in stats.hosts.values():
            writer.writerow(
                {
                    "ip_address": host.ip_addr,
                    "packets_sent": host.packets_sent,
                    "packets_received": host.packets_recv,
                    "bytes_sent": host.bytes_sent,
                    "bytes_received": host.bytes_recv,
                    "total_packets": host.tot_packets,
                    "total_bytes": host.tot_bytes
                }
            )

def export_protocol_summary_csv(
        stats: CaptureStats,
        filepath: Path
) -> None:
    """
    export prot distribution to csv file
    """
    fieldnames = ["protocol", "packets", "bytes", "percentage"]
    percentages = stats.get_prot_distribution()

    with filepath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for protocol, count in stats.prot_distribution.items():
            writer.writerow(
                {
                    "protocol": protocol.value,
                    "packets": count,
                    "bytes": stats.prot_bytes.get(protocol, 0),
                    "percentage": f"{percentages.get(protocol, 0.0):.2f}"
                }
            )

def load_from_json(filepath: Path) -> tuple[CaptureStats | None, list[PacketInfo]]:
    """
    load capture data from json file
    """
    with filepath.open(encoding="utf-8") as f:
        data = json.load(f)

    stats = None
    packets: list[PacketInfo] = []

    if "statistics" in data:
        stats_data = data["statistics"]
        stats = CaptureStats(
            t_start=stats_data.get("t_start", 0.0),
            t_end=stats_data.get("t_end", 0.0),
            packets_tot=stats_data.get("packets_tot", 0),
            bytes_tot=stats_data.get("bytes_tot", 0)
        )

        for prot_name, count in stats_data.get("protocol_distribution", {}).items():
            try:
                prot = Protocol(prot_name)
                stats.prot_distribution[prot] = count
            except ValueError:
                pass

    if "packets" in data:
        for pkt_data in data["packets"]:
            try:
                prot = Protocol(pkt_data.get("protocol", "OTHER"))
                packet = PacketInfo(
                    timestamp=pkt_data.get("timestamp", 0.0),
                    src_ip=pkt_data.get("src_ip", ""),
                    dest_ip=pkt_data.get("dest_ip", ""),
                    protocol=prot,
                    size=pkt_data.get("size", 0),
                    src_port=pkt_data.get("src_port"),
                    dest_port=pkt_data.get("dest_port"),
                    src_mac=pkt_data.get("src_mac"),
                    dest_mac=pkt_data.get("dest_mac")
                )
                packets.append(packet)
            except (KeyError, ValueError):
                pass
    return stats, packets

__all__ = [
    "export_hosts_csv",
    "export_packets_csv",
    "export_protocol_summary_csv",
    "export_to_json",
    "load_from_json",
    "packet_to_dict",
    "stats_to_dict"
]