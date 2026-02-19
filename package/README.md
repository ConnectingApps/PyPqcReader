# PQC Reader

TLS Post-Quantum Cryptography tracer for Python HTTP requests.

## Overview

`pqcreader` is a Python library that wraps HTTP requests to capture TLS handshake metadata, with a focus on post-quantum cryptography (PQC) key exchange groups like ML-KEM (formerly Kyber).

## Features

- 🔐 Capture TLS negotiated groups (including PQC algorithms like X25519MLKEM768)
- 🔍 Extract cipher suite information
- 🐍 Simple wrapper API for `requests` library
- 🐧 Linux-focused with OpenSSL integration
- 📦 Zero-configuration for basic usage

## Installation

```bash
pip install pqcreader
```

### Requirements

- Python 3.7+
- Linux operating system (required for OpenSSL tracing)
- OpenSSL 3.x

## Quick Start

### Basic Usage

```python
import requests
from pqcreader import pqcreader_request

# Wrap any requests call
response, tls_trace = pqcreader_request(
    lambda: requests.get("https://www.google.com", timeout=10)
)

print(f"Status: {response.status_code}")
print(f"Negotiated Group: {tls_trace.group}")
print(f"Cipher Suite: {tls_trace.cipher_suite}")
```

### Convenience Methods

```python
from pqcreader import pqcreader_get, pqcreader_post

# GET request
response, trace = pqcreader_get("https://example.com", timeout=10)

# POST request
response, trace = pqcreader_post(
    "https://api.example.com/data",
    json={"key": "value"},
    timeout=10
)
```

## How It Works

`pqcreader` uses monkey-patching to intercept `urllib3` HTTPS connections and extract the underlying OpenSSL SSL socket. It then uses `ctypes` to call OpenSSL functions directly to query TLS handshake metadata that isn't normally exposed by Python's `ssl` module.

## Limitations

- **Linux only**: Uses Linux-specific OpenSSL library loading
- **CPython only**: Relies on CPython internals for pointer extraction
- **Experimental**: May not work across all Python versions or OpenSSL configurations

## API Reference

### `pqcreader_request(request_callback, extract_trace=True)`

Execute an HTTP request with TLS tracing.

**Parameters:**
- `request_callback` (Callable): Function that performs the HTTP request
- `extract_trace` (bool): Whether to extract TLS trace (default: True)

**Returns:**
- `Tuple[Any, Optional[TlsTrace]]`: Response and TLS trace

### `pqcreader_get(url, **kwargs)`

Convenience wrapper for GET requests.

### `pqcreader_post(url, **kwargs)`

Convenience wrapper for POST requests.

### `TlsTrace`

Data class containing:
- `group` (str): Negotiated key exchange group
- `cipher_suite` (str): Negotiated cipher suite

## Examples

See the [`examples/`](examples/) directory for more usage examples.

## License

This project is licensed under the GNU General Public License v3.0 or later - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

This library is designed to help developers understand and test post-quantum cryptography deployment in TLS connections.
