import contextlib
import os
import platform
import signal
import socket
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from queue import Empty, Full, Queue
from typing import TYPE_CHECKING

from scapy.sendrecv import AsyncSniffer

from analyzer import extract_packet_info
from constants import CaptureDefaults, NpcapPaths
from models import CaptureConfig, CaptureStats, PacketInfo
from statistics import StatsCollector

if TYPE_CHECKING:
    from scapy.packet import Packet

class CaptureEngine:
    """
    packet capture engine using Scapy with producer-consumer pattern
    """
    def __init__(
            self,
            config: CaptureConfig,
            on_packet: Callable[[PacketInfo], None] | None = None,
            queue_size: int = CaptureDefaults.QUEUE_SIZE
    ) -> None:
        """
        initialize capture engine with config and optional packet callback
        """
        self._config = config
        self._on_packet = on_packet
        self._queue: Queue[Packet] = Queue(maxsize=queue_size)
        self._stats = StatsCollector()
        self._sniffer: AsyncSniffer | None = None
        self._proessor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._packet_count = 0
        self._dropped_packets = 0
        self._running = False
        self._count_lock = threading.Lock()

    def _enqueue_packet(self, packet: Packet) -> None:
        """
        callback for AsyncSniffer to enqueue captured packets
        """
        try:
            self._queue.put_nowait(packet)
        except Full:
            with self._count_lock:
                self._dropped_packets += 1

    def _process_packets(self) -> None:
        """
        consumer thread that processes packets from the queue
        """
        while not self._stop_event.is_set():
            try:
                packet = self._queue.get(
                    timeout=CaptureDefaults.QUEUE_TIMEOUT_SECONDS
                )
            except Empty:
                continue

            info = extract_packet_info(packet)
            if info is None:
                continue

            self._stats.record_packet(info)

            with self._count_lock:
                self._packet_count += 1
                current_count = self._packet_count

            if self._on_packet:
                self._on_packet(info)

            if self._config.packet_count and current_count >= self._config.packet_count:
                self._stop_event.set()
                break

    def start(self) -> None:
        """
        start packet capture
        """
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()

        with self._count_lock:
            self._packet_count = 0
            self._dropped_packets = 0
        
        self._stats.reset()
        self._stats.start()

        self._proessor_thread = threading.Thread(
            target=self._process_packets,
            daemon=True
        )
        self._proessor_thread.start()

        sniffer_kwargs: dict[str, object] = {
            "prn": self._enqueue_packet,
            "store": self._config.store_packets
        }

        if self._config.interface:
            sniffer_kwargs["iface"] = self._config.interface

        if self._config.bpf_filter:
            sniffer_kwargs["filter"] = self._config.bpf_filter

        if self._config.packet_count:
            sniffer_kwargs["count"] = self._config.packet_count

        if self._config.timeout_seconds:
            sniffer_kwargs["timeout"] = self._config.timeout_seconds

        self._sniffer = AsyncSniffer(**sniffer_kwargs)
        self._sniffer.start()

    def stop(self) -> CaptureStats:
        """
        stop packet capture and return stats
        """
        self._stop_event.set()

        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()

        if self._proessor_thread and self._proessor_thread.is_alive():
            self._proessor_thread.join(
                timeout=CaptureDefaults.THREAD_JOIN_TIMEOUT_SECONDS
            )

        self._running = False
        return self._stats.get_stats()
    
    def wait(self) -> CaptureStats:
        """
        wait for capture to complete and return stats
        """
        if self._sniffer:
            with contextlib.suppress(AttributeError):
                self._sniffer.join()

        self._stop_event.set()

        if self._proessor_thread and self._proessor_thread.is_alive():
            self._proessor_thread.join(
                timeout=CaptureDefaults.THREAD_JOIN_TIMEOUT_SECONDS
            )

        self._running = False
        return self._stats.get_stats()
    
    @property
    def stats(self) -> CaptureStats:
        """
        get current stats snapshot
        """
        return self._stats.get_stats()
    
    @property
    def is_running(self) -> bool:
        """
        check if capture is running right now
        """
        return self._running
    
    @property
    def dropped_packets(self) -> int:
        """
        get count of packets dropped due to queue being full
        """
        with self._count_lock:
            return self._dropped_packets
        
class GracefulCapture:
    """
    context manager for graceful capture with signal handling
    """
    def __init__(self, engine: CaptureEngine) -> None:
        """
        initialize with capture engine
        """
        self._engine = engine
        self._og_sigint: object = None
        self._og_sigterm: object = None

    def __enter__(self) -> CaptureEngine:
        """
        set up signal handlers and start capture
        """
        self._og_sigint = signal.signal(
            signal.SIGINT,
            self._handle_signal
        )

        self._og_sigterm = signal.signal(
            signal.SIGTERM,
            self._handle_signal
        )
        self._engine.start()
        return self._engine
    
    def __exit__(
            self,
            exc_type: type | None,
            exc_val: Exception | None,
            exc_tb: object,
    ) -> None:
        """
        restore signal handlers and stop capture
        """
        if self._og_sigint:
            signal.signal(signal.SIGINT, self._og_sigint) # type: ignore[arg-type]
        if self._og_sigterm:
            signal.signal(signal.SIGTERM, self._og_sigterm) # type: ignore[arg-type]
        self._engine.stop()

    def _handle_signal(self, _signum: int, _frame: object) -> None:
        """
        handle interrupt signals gracefully
        """
        self._engine.stop()
        sys.exit(0)

def capture_packets(
        interface: str | None = None,
        bpf_filter: str | None = None,
        count: int | None = None,
        timeout: float | None = None,
        on_packet: Callable[[PacketInfo], None] | None = None
) -> CaptureStats:
    """
    convenience function to capture packets with default settings
    """
    config = CaptureConfig(
        interface=interface,
        bpf_filter=bpf_filter,
        packet_count=count,
        timeout_seconds=timeout
    )

    engine = CaptureEngine(config=config, on_packet=on_packet)

    with GracefulCapture(engine):
        return engine.wait()
    
def get_available_interfaces() -> list[str]:
    """
    get list of availavle network interaces
    """
    try:
        from scapy.interfaces import get_if_list

        return list(get_if_list())
    except ImportError:
        return []
    
def check_capture_permissions() -> tuple[bool, str]:
    """
    check if current user has permissions for packet capture
    """
    system = platform.system()

    if system == "Linux":
        return _check_linux_permissions()
    elif system == "Darwin":
        return _check_macos_permissions()
    elif system == "Windows":
        return _check_windows_permissions()
    
    return False, f"Unknown platform: {system}"

def _check_linux_permissions() -> tuple[bool, str]:
    """
    check Linux permissions for packet capture by testing raw socket creation
    """
    if os.geteuid() == 0:
        return True, "Running as root"
    
    try:
        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003)
        )
        sock.close()
        return True, "Has CAP_NET_RAW permission"
    except PermissionError:
        return False, "Requires root or CAP_NET_RAW permission"
    except OSError as e:
        return False, f"Socket error: {e}"
    
def _check_macos_permissions() -> tuple[bool, str]:
    """
    check macOS permissions for packet capture by testing BPF device access
    """
    if os.geteuid() == 0:
        return True, "Running as root"
    
    bpf_devices = Path("/dev").glob("bpf*")
    for device in bpf_devices:
        if os.access(str(device), os.R_OK | os.W_OK):
            return True, f"Has access to {device}"
        
    return False, "Requires root or access to /dev/bpf* (install Wireshark for ChmodBPF)"

def _check_windows_permissions() -> tuple[bool, str]:
    """
    check Windows permissions for packet capture
    """
    npcap_installed = _check_npcap_installed()

    if not npcap_installed:
        return False, "Npcap is not installed (download from npcap.com)"

    is_admin = _check_windows_admin()

    if not is_admin:
        return False, "Requires Administrator privileges"

    return True, "Running as Administrator with Npcap"

def _check_npcap_installed() -> bool:
    """
    check if npcap DLL exists on Windows
    """
    npcap_paths = [NpcapPaths.SYSTEM32, NpcapPaths.SYSWOW64]
    return any(Path(p).exists() for p in npcap_paths)

def _check_windows_admin() -> bool:
    """
    check if running as Administrator on Windows
    """
    try:
        import ctypes

        return ctypes.windll.shell32.IsUserAdmin() != 0
    except(AttributeError, OSError):
        return False
    
__all__ = [
    "CaptureConfig",
    "CaptureEngine",
    "GracefulCapture",
    "capture_packets",
    "check_capture_permissions",
    "get_available_interfaces"
]