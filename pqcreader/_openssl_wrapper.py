"""
OpenSSL wrapper for extracting TLS handshake metadata
"""
import ctypes
import platform
from ctypes import c_void_p, c_int, c_long, c_char_p
from dataclasses import dataclass
from typing import Optional, Tuple

# OpenSSL constants
SSL_CTRL_GET_NEGOTIATED_GROUP = 134


@dataclass(frozen=True)
class TlsTrace:
    """Container for TLS handshake metadata"""
    group: str
    cipher_suite: str


def is_linux() -> bool:
    """Check if running on Linux platform"""
    return platform.system() == "Linux"


def load_openssl_functions() -> Tuple[Optional[any], Optional[any]]:
    """Load OpenSSL functions via ctypes"""
    try:
        # Try to load libssl.so.3
        libssl = ctypes.CDLL("libssl.so.3")
    except OSError:
        try:
            # Fallback to libssl.so.1.1
            libssl = ctypes.CDLL("libssl.so.1.1")
        except OSError:
            try:
                # Fallback to libssl.so
                libssl = ctypes.CDLL("libssl.so")
            except OSError:
                return None, None

    # SSL_ctrl function signature:
    # long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
    ssl_ctrl = libssl.SSL_ctrl
    ssl_ctrl.argtypes = [c_void_p, c_int, c_long, c_void_p]
    ssl_ctrl.restype = c_long

    # SSL_group_to_name function signature:
    # const char *SSL_group_to_name(SSL *ssl, int id)
    ssl_group_to_name = libssl.SSL_group_to_name
    ssl_group_to_name.argtypes = [c_void_p, c_int]
    ssl_group_to_name.restype = c_char_p

    return ssl_ctrl, ssl_group_to_name


def get_ssl_pointer(ssl_socket) -> Optional[int]:
    """
    Extract the native SSL* pointer from a Python SSLSocket object.

    This uses ctypes to access the internal _sslobj attribute and extract
    the underlying OpenSSL SSL* pointer.
    """
    try:
        # Get the internal _ssl._SSLSocket object
        ssl_obj = ssl_socket._sslobj  # pylint: disable=protected-access

        if ssl_obj is None:
            return None

        # The _ssl._SSLSocket object is a C extension object that
        # wraps the SSL* pointer. We need to extract the pointer
        # using ctypes

        # Get the id of the Python object, which is its memory address
        obj_id = id(ssl_obj)

        # For CPython, we can access the PyObject structure
        # The SSL* pointer is typically stored in the object's
        # internal structure

        # This is a fragile approach that depends on CPython internals
        # For a more robust solution, we would need to use a custom
        # C extension

        # Try to get the SSL pointer through the _ssl module's
        # internal structure. _ssl module is imported at the top level

        # Access the internal pointer - this is implementation-specific
        # The _ssl._SSLSocket object contains the SSL* pointer
        # We need to use ctypes to extract it

        # Create a ctypes structure to match the Python object layout
        # pylint: disable=unused-variable,too-few-public-methods
        # Note: PyObject and _ssl are used for understanding
        # internal structure

        # For _ssl._SSLSocket, the SSL* pointer is stored after
        # the PyObject header. This offset varies by Python version
        # and implementation

        # Alternative: Use the socket's fileno() to get the file descriptor,
        # but this won't give us the SSL* pointer directly

        # More reliable approach: Access through the underlying BIO
        # But Python's ssl module doesn't expose this easily

        # For now, we'll use a platform-specific approach
        # that works with the internal structure of _ssl._SSLSocket

        # The SSL* pointer is typically at a fixed offset in the
        # _SSLSocket structure. This is highly implementation-dependent

        # Cast the ssl_obj to a ctypes void pointer to extract
        # internal data. Note: This is a hack and may not work across
        # all Python versions

        # Try to access via ctypes pointer manipulation
        ssl_obj_ptr = ctypes.cast(obj_id, ctypes.POINTER(ctypes.c_void_p))

        # The SSL* pointer is typically stored at a specific offset
        # For CPython 3.x, it's usually at offset 24 or 32 bytes
        # from the object start (after ob_refcnt, ob_type, and other
        # fields)

        # Try multiple common offsets
        # These are word offsets (multiply by pointer size)
        for offset in [3, 4, 5, 6]:
            try:
                potential_ssl_ptr = ssl_obj_ptr[offset]
                if potential_ssl_ptr and potential_ssl_ptr != 0:
                    # Verify this looks like a valid pointer
                    if 0x1000 < potential_ssl_ptr < 0x7fffffffffff:
                        return potential_ssl_ptr
            except (IndexError, ValueError, OSError):
                continue

        return None

    except Exception:  # pylint: disable=broad-exception-caught
        return None


def get_negotiated_group(
    ssl_socket, 
    ssl_ctrl_func,
    ssl_group_to_name_func
) -> str:
    """
    Query OpenSSL for the negotiated key exchange group.

    Returns the group name (e.g., "X25519", "X25519MLKEM768") or an
    error message.
    """
    try:
        # Get the native SSL* pointer
        ssl_ptr = get_ssl_pointer(ssl_socket)

        if ssl_ptr is None:
            return "Err: Handle Not Found"

        # Call SSL_ctrl to get the negotiated group ID
        group_id = ssl_ctrl_func(
            ssl_ptr, SSL_CTRL_GET_NEGOTIATED_GROUP, 0, None)

        if group_id == 0:
            return "Unknown (GroupID=0)"

        # Call SSL_group_to_name to get the group name
        group_name_ptr = ssl_group_to_name_func(ssl_ptr, int(group_id))

        if group_name_ptr is None:
            return f"Decode Error (GroupID={group_id})"

        # Decode the C string to Python string
        group_name = group_name_ptr.decode('utf-8')
        return group_name

    except Exception as e:  # pylint: disable=broad-exception-caught
        return f"Err: {str(e)}"


def get_cipher_suite(ssl_socket) -> str:
    """Get the negotiated cipher suite from the SSL socket"""
    try:
        cipher = ssl_socket.cipher()
        if cipher:
            # cipher() returns a tuple: (name, version, bits)
            return cipher[0]
        return "Unknown"
    except (AttributeError, OSError):
        return "Unknown"
