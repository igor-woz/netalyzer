class NetAlyzerError(Exception):
    """
    Base exception for all errors
    """

class CaptureError(NetAlyzerError):
    """
    Erorrs related to packet capture ops
    """

class CapturePermissionError(CaptureError):
    """
    Insufficient permissions for packet capture
    """

class NpcapNotFoundError(CaptureError):
    """
    Npcap not installed on Windows
    """

class InvalidFilterError(NetAlyzerError):
    """
    Invalid BPF filter expression
    """

class ExportError(NetAlyzerError):
    """
    Errors during data export operations
    """

class AnalysisError(NetAlyzerError):
    """
    Errors during packet analysis
    """

class ValidationError(NetAlyzerError):
    """
    Input validation errors
    """

__all__ = [
    "AnalysisError",
    "CaptureError",
    "CapturePermissionError",
    "ExportError",
    "InvalidFilterError",
    "NetAlyzerError",
    "NpcapNotFoundError",
    "ValidationError",
]