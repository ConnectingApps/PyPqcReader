"""
PQC Reader - TLS trace wrapper for HTTP requests
"""
from typing import Callable, Tuple, Any, Optional
from urllib3.connection import HTTPSConnection

from openssl_wrapper import (
    is_linux,
    load_openssl_functions,
    get_negotiated_group,
    get_cipher_suite,
    TlsTrace
)


def pqcreader_request(
    request_callback: Callable[[], Any],
    extract_trace: bool = True
) -> Tuple[Any, Optional[TlsTrace]]:
    """
    Execute an HTTP request with TLS tracing capability.
    
    Args:
        request_callback: A callable that performs the actual HTTP request
                         (e.g., lambda: requests.get(url, timeout=10))
        extract_trace: Whether to extract TLS trace (default: True)
    
    Returns:
        Tuple of (response, tls_trace):
        - response: The return value from request_callback
        - tls_trace: TlsTrace object or None if extraction disabled/failed
    
    Example:
        >>> response, trace = pqcreader_request(
        ...     lambda: requests.get("https://www.google.com", timeout=10)
        ... )
        >>> print(f"Status: {response.status_code}")
        >>> print(f"Group: {trace.group}")
    """
    if not extract_trace or not is_linux():
        # No tracing - just execute the callback
        response = request_callback()
        fallback_trace = TlsTrace("Non-Linux", "N/A") if not is_linux() else None
        return response, fallback_trace
    
    # Load OpenSSL functions
    ssl_ctrl_func, ssl_group_to_name_func = load_openssl_functions()
    
    if ssl_ctrl_func is None or ssl_group_to_name_func is None:
        response = request_callback()
        return response, TlsTrace("Err: OpenSSL library not found", "N/A")
    
    try:
        # Capture SSL socket during connection
        captured_ssl_sock = [None]
        original_connect = HTTPSConnection.connect
        
        def patched_connect(self):
            original_connect(self)
            if hasattr(self, 'sock') and self.sock:
                captured_ssl_sock[0] = self.sock
        
        # Monkey-patch and execute request
        HTTPSConnection.connect = patched_connect
        try:
            response = request_callback()
        finally:
            HTTPSConnection.connect = original_connect
        
        # Extract TLS metadata
        if captured_ssl_sock[0] is None:
            tls_trace = TlsTrace("Err: Could not access SSL socket", "N/A")
        else:
            group_name = get_negotiated_group(
                captured_ssl_sock[0], ssl_ctrl_func, ssl_group_to_name_func
            )
            cipher_suite = get_cipher_suite(captured_ssl_sock[0])
            tls_trace = TlsTrace(group_name, cipher_suite)
        
        return response, tls_trace
    
    except Exception as e:
        # If request_callback raises, we still propagate it but with trace info
        tls_trace = TlsTrace(f"Err: {str(e)}", "N/A")
        raise


def pqcreader_get(url: str, **kwargs) -> Tuple[Any, Optional[TlsTrace]]:
    """
    Convenience wrapper for GET requests with TLS tracing.
    
    Args:
        url: Target URL
        **kwargs: Additional arguments passed to requests.get
    
    Returns:
        Tuple of (response, tls_trace)
    """
    import requests
    return pqcreader_request(lambda: requests.get(url, **kwargs))


def pqcreader_post(url: str, **kwargs) -> Tuple[Any, Optional[TlsTrace]]:
    """
    Convenience wrapper for POST requests with TLS tracing.
    
    Args:
        url: Target URL
        **kwargs: Additional arguments passed to requests.post
    
    Returns:
        Tuple of (response, tls_trace)
    """
    import requests
    return pqcreader_request(lambda: requests.post(url, **kwargs))
