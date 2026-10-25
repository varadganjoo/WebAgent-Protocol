"""Optional decentralized business discovery. Transactions always go to verified business domains."""

from ..spec.discovery import BusinessDiscovery, GeoPoint, ServiceArea
from .client import BusinessSearchResult, DirectoryClient, VerifiedBusiness
from .models import DirectoryEntry, DirectoryPage, DirectoryQuery
from .providers import DirectoryError, DirectoryProvider, HTTPDirectory, MemoryDirectory

__all__ = [
    "BusinessDiscovery",
    "BusinessSearchResult",
    "DirectoryClient",
    "DirectoryEntry",
    "DirectoryError",
    "DirectoryPage",
    "DirectoryProvider",
    "DirectoryQuery",
    "GeoPoint",
    "HTTPDirectory",
    "MemoryDirectory",
    "ServiceArea",
    "VerifiedBusiness",
]
