import ipaddress
from dataclasses import dataclass
from typing import Literal, Self

from constants import PortRange, Ports
from exceptions import ValidationError
from models import Protocol

BPF_PROTOCOL_MAP: dict[Protocol,
                       str] = {
                           Protocol.TCP: "tcp",
                           Protocol.UDP: "udp",
                           Protocol.ICMP: "icmp",
                           Protocol.ARP: "arp",
                           Protocol.DNS:
                           f"udp port {Ports.DNS} or tcp port {Ports.DNS}",
                           Protocol.HTTP: f"tcp port {Ports.HTTP}",
                           Protocol.HTTPS: f"tcp port {Ports.HTTPS}"
                       }

def _validate_port(port_number: int) -> None:
    """
    validate that a port number is within valid range
    """
    if not PortRange.MIN <= port_number <= PortRange.MAX:
        raise ValidationError(
            f"Port must be {PortRange.MIN}-{PortRange.MAX}, got: {port_number}"
        )

def _validate_ip_addr(ip_addr: str) -> None:
    """
    validate IP address format
    """
    try:
        ipaddress.ip_address(ip_addr)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {ip_addr}") from e

def _validate_network(network: str) -> None:
    """
    validate network CIDR notation
    """    
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        raise ValidationError(f"Invalid network: {network}") from e
    
@dataclass(slots=True)
class FilterBuilder:
    """
    builds BPF filter expressions for efficient kernel-level packet filtering
    """
    _expressions: list[str]

    def __init__(self) -> None:
        """
        initialize empty filter builder
        """
        self._expressions = []

    def protocol(self, prot: Protocol) -> Self:
        """
        filter by protocol type using the Protocol enum
        """
        bpf_expr = BPF_PROTOCOL_MAP.get(prot)
        if bpf_expr:
            self._expressions.append(f"({bpf_expr})")
        return self
    
    def protocols(self, prots: list[Protocol]) -> Self:
        """
        filter by multiple protocols (or logic)
        """
        bpf_exprs = [
            BPF_PROTOCOL_MAP[p] for p in prots if p in BPF_PROTOCOL_MAP
        ]
        if bpf_exprs:
            combined = " or ".join(f"({expr})" for expr in bpf_exprs)
            self._expressions.append(f"({combined})")
        return self
    
    def port(self, port_number: int) -> Self:
        """
        filter by port number (src or dest)
        """
        _validate_port(port_number)
        self._expressions.append(f"port {port_number}")
        return self
    
    def src_port(self, port_number: int) -> Self:
        """
        filter by src port
        """
        _validate_port(port_number)
        self._expressions.append(f"src port {port_number}")
        return self
    
    def dest_port(self, port_number: int) -> Self:
        """
        filter by dest port
        """
        _validate_port(port_number)
        self._expressions.append(f"dst port {port_number}")
        return self
    
    def host(self, ip_addr: str) -> Self:
        """
        filter by IP address (src or dest)
        """
        _validate_ip_addr(ip_addr)
        self._expressions.append(f"host {ip_addr}")
        return self
    
    def src_host(self, ip_addr: str) -> Self:
        """
        filter by src IP address
        """
        _validate_ip_addr(ip_addr)
        self._expressions.append(f"src host {ip_addr}")
        return self
    
    def dest_host(self, ip_addr: str) -> Self:
        """
        filter by dest IP address
        """
        _validate_ip_addr(ip_addr)
        self._expressions.append(f"dst host {ip_addr}")
        return self
    
    def network(self, network: str) -> Self:
        """
        filter by network (CIDR notation)
        """
        _validate_network(network)
        self._expressions.append(f"net {network}")
        return self
    
    def port_range(self, start: int, end: int) -> Self:
        """
        filter by port range
        """
        _validate_port(start)
        _validate_port(end)
        if start > end:
            raise ValidationError(f"Invalid port range: {start}-{end}")
        self._expressions.append(f"portrange {start}-{end}")
        return self
    
    def not_port(self, port_number: int) -> Self:
        """
        exclude traffic on specified port
        """
        _validate_port(port_number)
        self._expressions.append(f"not port {port_number}")
        return self
    
    def not_host(self, ip_addr: str) -> Self:
        """
        exclude traffic from/to specified host
        """
        _validate_ip_addr(ip_addr)
        self._expressions.append(f"not host {ip_addr}")
        return self
    
    def raw(self, expression: str) -> Self:
        """
        add raw BPF expression fro advanced filtering
        """
        self._expressions.append(expression)
        return self
    
    def build(self, operator: Literal["and", "or"] = "and") -> str | None:
        """
        build final BPF filter string combining all expressions
        """
        if not self._expressions:
            return None
        return f" {operator} ".join(self._expressions)
    
    def reset(self) -> Self:
        """
        clear all filter expressions
        """
        self._expressions = []
        return self
    
def prot_to_bpf(prot: Protocol) -> str | None:
    """
    convert Protocol enum to BPF filter expression
    """
    return BPF_PROTOCOL_MAP.get(prot)
    
def combine_filters(
        filters: list[str],
        operator: Literal["and", "or"] = "and"
) -> str | None:
    """
    combine multiple BPF filter string with logical operator
    """
    valid_filters = [f for f in filters if f]
    if not valid_filters:
        return None
    if len(valid_filters) == 1:
        return valid_filters[0]
    wrapped = [f"({f})" for f in valid_filters]
    return f" {operator} ".join(wrapped)
    
def validate_bpf_filter(filter_str: str ) -> bool:
    """
    validate BPF filter syntax using Scapy
    """
    try:
        from scapy.arch import compile_filter

        compile_filter(filter_str)
        return True
    except Exception:
        return False
    
__all__ = [
    "BPF_PROTOCOL_MAP",
    "FilterBuilder",
    "combine_filters",
    "prot_to_bpf",
    "validate_bpf_filter"
]
        
    