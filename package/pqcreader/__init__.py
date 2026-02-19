"""
PQC Reader - TLS Post-Quantum Cryptography Tracer

A Python library for tracing TLS handshake metadata, including 
post-quantum cryptography key exchange groups.
"""

from pqcreader._openssl_wrapper import TlsTrace
from pqcreader._pqcreader import (
    pqcreader_request,
    pqcreader_get,
    pqcreader_post,
)

__version__ = "0.1.0"
__author__ = "Daan Acohen"
__all__ = [
    "pqcreader_request",
    "pqcreader_get", 
    "pqcreader_post",
    "TlsTrace",
]
