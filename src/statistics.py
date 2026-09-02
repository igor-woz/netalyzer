import threading
import time
from collections import defaultdict

from constants import CaptureDefaults
from models import (
    BandwidthSample,
    CaptureStats,
    ConvoStats,
    HostStats,
    PacketInfo,
    Protocol
)

class StatsCollector:
    """
    thread-safe collector for packet capture stats
    """
    def __init__(
        self,
        bandwidth_interval: float = CaptureDefaults.
        BANDWIDTH_SAMPLE_INTERVAL_SECONDS
        ) -> None:
        """
        initialize stats collector with bandwidth sampling interval
        """
        self._lock = threading.Lock()
        self._bandwidth_interval = bandwidth_interval

        self._t_start: float = 0.0
        self._t_last_sample: float = 0.0
        self._interval_bytes: int = 0
        self._interval_packets: int = 0

        self._packets_tot: int = 0
        self._bytes_tot: int = 0
        self._prot_counts: dict[Protocol, int] = defaultdict(int)
        self._prot_bytes: dict[Protocol, int] = defaultdict(int)
        self._hosts: dict[str, HostStats] = {}
        self._convos: dict[tuple[str, str], ConvoStats] = {}
        self._bandwidth_samples: list[BandwidthSample] = []

    def start(self) -> None:
        """
        mark the start of a capture session
        """
        with self._lock:
            self._t_start = time.time()
            self._t_last_sample = self._t_start

    def record_packet(self, packet: PacketInfo) -> None:
        """
        record stats for a captured packet (thread-safe)
        """
        with self._lock:
            self._packets_tot += 1
            self._bytes_tot += packet.size
            self._interval_packets += 1
            self._interval_bytes += packet.size

            self._prot_counts[packet.protocol] += 1
            self._prot_bytes[packet.protocol] += packet.size

            self._
        
    def _update_host(
        self, 
        ip_addr: str,
        sent_bytes: int = 0,
        recv_bytes: int = 0
    ) -> None:
        """
        update stats for a host
        """
        if ip_addr not in self._hosts:
            self._hosts[ip_addr] = HostStats(
                ip_addr=ip_addr
            )

        host = self._hosts[ip_addr]
        if sent_bytes > 0:
            host.packets_sent += 1
            host.bytes_sent += sent_bytes
        if recv_bytes > 0:
            host.packets_recv += 1
            host.bytes_recv += recv_bytes

    def _update_convo(
        self,
        src_ip: str,
        dst_ip: str,
        size: int
    ) -> None:
        """
        updates stats for a convo between two hosts
        """
        key = tuple(sorted([src_ip, dst_ip]))
        convo_key = (key[0], key[1])

        if convo_key not in self._convos:
            self._convos[convo_key] = ConvoStats(
                host_1=convo_key[0],
                host_2=convo_key[1]
            )

        convo = self._convos[convo_key]
        convo.packets_tot += 1
        convo.bytes_tot += size

    def _check_bandwidth_sample(self, timestamp: float) -> None:
        """
        check if sample interval has ended and record if yes
        """
        if timestamp - self._t_last_sample >= self._bandwidth_interval:
            elapsed = timestamp - self._t_last_sample
            if elapsed > 0:
                bps = self._interval_bytes / elapsed
                pps = self._interval_packets / elapsed
                self._bandwidth_samples.append(
                    BandwidthSample(
                        timestamp=timestamp,
                        bytes_per_sec=bps,
                        packets_per_sec=pps
                    )
                )
            self._interval_bytes = 0
            self._interval_packets = 0
            self._t_last_sample = timestamp

    def get_stats(self) -> CaptureStats:
        """
        get current capture stats snapshot (thread-safe)
        """
        with self._lock:
            return CaptureStats(
                t_start=self._t_start,
                t_end=time.time(),
                packets_tot=self._packets_tot,
                bytes_tot=self._bytes_tot,
                prot_distribution=dict(self._prot_counts),
                prot_bytes=dict(self._prot_bytes),
                hosts=dict(self._hosts),
                convo=dict(self._convos),
                bandwidth_samples=list(self._bandwidth_samples)
            )

    def reset(self) -> None:
        """
        reset all stats to initial state
        """
        with self._lock:
            self._start_time = 0.0
            self._last_sample_time = 0.0
            self._interval_bytes = 0
            self._interval_packets = 0
            self._total_packets = 0
            self._total_bytes = 0
            self._protocol_counts = defaultdict(int)
            self._protocol_bytes = defaultdict(int)
            self._endpoints = {}
            self._conversations = {}
            self._bandwidth_samples = []

    @property
    def packet_count(self) -> int:
        """
        get current packet count (thread-safe)
        """
        with self._lock:
            return self._packets_tot

    @property
    def byte_count(self) -> int:
        """
        get current byte count (thread-safe)
        """
        with self._lock:
            return self._bytes_tot

__all__ = [
    "StatsCollector"
]  
    