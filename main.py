#!/usr/bin/env python3
"""
TLS Post-Quantum Cryptography Tracer - Application Entry Point
"""
import sys
import requests
from pqcreader import pqcreader_request


def main():
    """Main entry point"""
    # Default target URL
    target_url = "https://www.google.com"

    # Allow URL to be passed as command line argument
    if len(sys.argv) > 1:
        target_url = sys.argv[1]

    print(f"Making HTTPS request to: {target_url}")
    print()

    try:
        # Use the pqcreader wrapper with a callback
        response, tls_trace = pqcreader_request(
            lambda: requests.get(target_url, timeout=10)
        )

        print(f"Status Code: {response.status_code}")
        
        if tls_trace:
            print(f"Negotiated Group: {tls_trace.group}")
            print(f"Cipher Suite: {tls_trace.cipher_suite}")
        else:
            print("TLS Trace not found.")

    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
