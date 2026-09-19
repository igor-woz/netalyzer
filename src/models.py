"""
ⒸIgor Wozniak | 2026
models.py

Data models for packet capture and network traffic analysis

Defines all shared data structures used across the project

Key exports:
    Protocol - StrEnum of network protocols
    PacketInfo - frozen dataclass for a single packet
    HostStats - counters for a specific IP with total packets and bytes
    CommunicationsStats - bidirectional stats between two IPs
    BandwidthSample - point-in-time bandwidth state
    CaptureStats - full session stats
    CaptureConfig - frozen config for a capture session
    ExportOpts - flags that control what to input in export output

"""

from dataclasses import dataclass, field
from enum import StrEnum

class Protocol(StrEnum):
    """
    network protocols identified during packet analysis
    """
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    ARP = "ARP"
    OTHER = "OTHER"

@dataclass(frozen=True, slots=True)
class PacketInfo():
    """
    information extracted from a single packet that was captured
    """
    timestamp: float
    src_ip: str
    dest_ip: str
    protocol: Protocol
    size: int
    src_port: int | None = None
    dest_port: int | None = None
    src_mac: str  | None = None 
    dest_mac: str  | None = None

@dataclass(slots=True)
class HostStats:
    """
    traffic stats for a single host
    """
    ip_addr: str
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0

    @property
    def tot_packets(self) -> int:
        """
        calculate total packets for this host
        """
        return self.packets_sent + self.packets_recv
    
    @property
    def tot_bytes(self) -> int:
        """
        calculate total bytes for this host
        """
        return self.bytes_sent + self.bytes_recv
    
@dataclass(slots=True)
class ConvoStats:
    """
    traffic stats for communication between two hosts
    """
    host_1: str
    host_2: str
    packets_tot: int = 0
    bytes_tot: int = 0

@dataclass(slots=True)
class BandwidthSample:
    """
    state of bandwith at a point in time
    """
    timestamp: float
    packets_per_sec: float
    bytes_per_sec: float

@dataclass(slots=True)
class CaptureStats:
    """
    collection of stats for a capture session
    """
    t_start: float = 0.0
    t_end: float = 0.0
    packets_tot: int = 0
    bytes_tot: int = 0
    prot_distribution: dict[Protocol, int] = field(default_factory=dict)
    prot_bytes: dict[Protocol, int] = field(default_factory=dict)
    hosts: dict[str, HostStats] = field(default_factory=dict)
    convo: dict[tuple[str, str], ConvoStats] = field(default_factory=dict)
    bandwidth_samples: list[BandwidthSample] = field(default_factory=list)

    @property
    def capture_time(self) -> float:
        """
        calculate capture time in seconds
        """
        if self.t_end <= self.t_start:
            return 0.0
        return self.t_end - self.t_start
    
    @property
    def bandwidth_avg(self) -> float:
        """
        calculate averabe bandwidth in B/s
        """
        capture_time = self.capture_time
        if capture_time <= 0:
            return 0.0
        return self.bytes_tot / capture_time
    
    def get_top_hosts(self, limit: int = 10) -> list[HostStats]:
        """
        return hosts sorted by total bytes
        """
        sorted_hosts = sorted(
            self.hosts.values(), 
            key=lambda e: e.tot_bytes, 
            reverse=True
            )
        return sorted_hosts[: limit]
    
    def get_prot_distribution(self) -> dict[Protocol, float]:
            """
            calculate protocol distribution as %
            """
            if self.packets_tot == 0:
                return {}
            return {
                prot: (count / self.packets_tot) * 100
                for prot, count in self.prot_distribution.items()
            }
    
@dataclass(frozen=True, slots=True)
class CaptureConfig:
    """
    config for a capture session
    """
    interface: str | None = None
    bpf_filter: str | None = None
    packet_count: int | None = None
    timeout_seconds: float | None = None
    promiscuous: bool = True
    store_packets: bool = False

@dataclass(frozen=True, slots=True)
class ExportOpts:
    """
    options for exporting capture data
    """
    include_packets: bool = True
    include_stats: bool = True
    include_hosts: bool = True
    include_convos: bool = True
    pretty_print: bool = True