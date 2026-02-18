Collecting workspace information# Technical Description: TLS Post-Quantum Cryptography Tracer (Outgoing HTTP Client)

## Purpose

This application makes an HTTPS request to a remote server (e.g., `https://www.google.com`) and inspects the **TLS handshake** that was negotiated at the transport layer. It extracts and prints:

1. **The key exchange group** (e.g., `X25519`, `X25519MLKEM768`) — reveals whether the connection used post-quantum cryptography.
2. **The cipher suite** (e.g., `TLS_AES_256_GCM_SHA384`) — the symmetric encryption algorithm negotiated for the session.

The goal is to determine whether an outgoing HTTPS connection is **quantum-resistant** (i.e., uses ML-KEM / Kyber-based key exchange).

---

## High-Level Flow

1. **Create a TCP connection** to the target host and port.
2. **Perform a TLS handshake** over that TCP connection (as a client).
3. **After the handshake completes**, access the underlying native SSL object to query what key exchange group was negotiated.
4. **Store the TLS trace** (group name + cipher suite) alongside the HTTP request/response so it can be retrieved after the HTTP call completes.
5. **Print the results** to standard output.

---

## Detailed Steps

### Step 1: Intercept the Connection

The application uses a custom HTTP handler that wraps the standard socket-based HTTP handler. It overrides the **connect callback** — the function responsible for establishing the underlying transport connection before HTTP-level communication begins.

When the HTTP client needs to connect to a server:

1. Open a **TCP socket** to `host:port`.
2. If the scheme is `https`, wrap the TCP stream in a **TLS stream** (client-side).
3. Perform the TLS handshake (`AuthenticateAsClient`) with:
   - **Target host** set to the server's hostname (for SNI).
   - An optional **certificate validation callback** (by default, only connections with no policy errors are accepted).
4. After the handshake succeeds, **extract TLS metadata** (see Step 2).
5. If any error occurs during TLS setup, clean up all resources (TLS stream, TCP stream, socket).

### Step 2: Extract TLS Metadata from the Native SSL Handle

This is the core technical challenge. The TLS stream object in most runtimes wraps a native OpenSSL `SSL*` pointer internally but does not expose the negotiated key exchange group through any public API. The application must:

#### 2a: Locate the Native SSL Handle via Reflection

The TLS/SSL stream object contains the native handle buried several levels deep in private fields. The algorithm to find it:

1. **Start from the TLS stream object** itself.
2. **Recursively scan private instance fields** up to a depth of 4 levels:
   - Skip primitive types and strings.
   - Only follow fields whose type's fully qualified name starts with `"System.Net"` (or whatever namespace the runtime's networking internals use — this is .NET-specific filtering; in other languages, follow internal SSL-related types).
   - For each field value, check if it is a **native handle wrapper** (a safe handle / file descriptor pointing to the `SSL*` object).
   - The handle is identified by checking if the type name contains `"Context"` or `"Ssl"` and the handle is valid (not closed, not invalid/null).
3. **Cache the field path** on first discovery. Subsequent calls reuse the cached path of field accessors for performance (avoid repeated reflection).

The result is a pointer (or handle) to the native OpenSSL `SSL` structure.

#### 2b: Query OpenSSL for the Negotiated Group

Once you have the native `SSL*` pointer, call two OpenSSL functions from `libssl.so.3`:

##### Function 1: `SSL_ctrl`

```
long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
```

- **Library**: `libssl.so.3`
- **Parameters**:
  - `ssl`: The native SSL pointer obtained in step 2a.
  - `cmd`: `134` — this is the constant `SSL_CTRL_GET_NEGOTIATED_GROUP` defined in OpenSSL's `ssl.h`.
  - `larg`: `0`
  - `parg`: `NULL` (null pointer)
- **Returns**: A `long` value representing the **NID (Numeric ID)** of the negotiated key exchange group.
  - `0` means no group was negotiated (or not available).

##### Function 2: `SSL_group_to_name`

```
const char *SSL_group_to_name(SSL *ssl, int id)
```

- **Library**: `libssl.so.3`
- **Parameters**:
  - `ssl`: The same native SSL pointer.
  - `id`: The group NID returned by `SSL_ctrl`.
- **Returns**: A pointer to a null-terminated C string with the human-readable group name (e.g., `"X25519"`, `"X25519MLKEM768"`).
  - Returns `NULL` if the ID cannot be decoded.

> **Important**: `SSL_group_to_name` is preferred over `OBJ_nid2sn` because TLS 1.3 groups (especially hybrid PQC groups) may not have NID entries in the OBJ database. `SSL_group_to_name` was added in OpenSSL 3.0 specifically for this purpose.

#### 2c: Get the Cipher Suite

The cipher suite is available directly from the TLS stream's public API (e.g., `NegotiatedCipherSuite` property). Its string representation (e.g., `"TLS_AES_256_GCM_SHA384"`) is captured.

### Step 3: Store and Retrieve the Trace

The extracted group name and cipher suite are packaged into a record/struct:

```
TlsTrace {
    Group: string        // e.g., "X25519MLKEM768"
    CipherSuite: string  // e.g., "TLS_AES_256_GCM_SHA384"
}
```

This is stored as a **key-value option on the HTTP request message** (using the key `"TlsTrace"`). After the HTTP response is received, the trace is retrieved from the response's associated request options.

### Step 4: Output

The application prints:

```
Negotiated Group: <group_name>
Cipher Suite: <cipher_suite>
```

If the trace is not found (e.g., non-HTTPS connection or extraction failed), it prints:

```
TLS Trace not found.
```

If an HTTP-level error occurs, it prints:

```
Error: <message>
```

---

## Dependencies

### Required Shared Library

| Library | Minimum Version | Functions Used |
|---------|----------------|----------------|
| `libssl.so.3` | OpenSSL 3.0+ (3.5.0+ for PQC/ML-KEM support) | `SSL_ctrl`, `SSL_group_to_name` |

Both functions are loaded via dynamic linking (P/Invoke, `dlopen`/`dlsym`, FFI, or equivalent in the target language).

### Platform Constraint

- **Linux only**. The native OpenSSL inspection only works on Linux where the runtime uses OpenSSL as its TLS backend.
- On macOS and Windows, the TLS negotiation group extraction is **not supported** (returns `"Non-Linux"`). These platforms use different native TLS libraries (Secure Transport on macOS, SChannel on Windows) that don't expose the same API.

---

## OpenSSL Constants Reference

| Constant Name | Value | Source |
|---------------|-------|--------|
| `SSL_CTRL_GET_NEGOTIATED_GROUP` | `134` | `openssl/ssl.h` |

---

## Expected Group Values

| Group Name | Quantum-Resistant? | OpenSSL Version Required |
|---|---|---|
| `X25519` | No (classical) | 3.0+ |
| `X25519MLKEM768` | **Yes** (hybrid PQC) | 3.5.0+ |
| `P-256` | No (classical) | 3.0+ |

---

## Error Handling Summary

| Return Value | Meaning |
|---|---|
| `"Non-Linux"` | Running on an unsupported platform |
| `"Err: Handle Not Found"` | Could not locate the native `SSL*` pointer via reflection |
| `"Unknown (GroupID=0)"` | `SSL_ctrl` returned `0` — no group negotiated |
| `"Decode Error (GroupID=N)"` | `SSL_group_to_name` returned `NULL` for group ID N |
| `"Err: <message>"` | Any other exception during native call |

---

## Implementation Notes for Other Languages

1. **Accessing the native `SSL*` pointer**: This is the hardest part. In .NET, the handle is buried in private fields requiring reflection. In other languages:
   - **Python** (`ssl` module): Use `ssl.SSLSocket` → access the underlying `_sslobj` → use `ctypes` to get the `SSL*` pointer from the `_ssl._SSLSocket` C object.
   - **Go**: The `crypto/tls` package does not use OpenSSL; you'd need to use a CGo-based TLS library or call OpenSSL directly.
   - **C/C++**: Direct access — you already have the `SSL*` pointer from `SSL_new()`.
   - **Java**: Use JNI or a library like Conscrypt/BoringSSL; inspect the native SSL handle from the SSLEngine.
   - **Rust**: Use the `openssl` crate which gives direct access to `SslRef` and its method `ssl_ctrl`.

2. **The key insight**: After the TLS handshake completes but before HTTP data flows, you must intercept the established SSL session and call `SSL_ctrl(ssl, 134, 0, NULL)` followed by `SSL_group_to_name(ssl, group_id)`.

3. **Thread safety**: The reflection path cache (for locating the native handle) should be thread-safe. Use an atomic/volatile store or equivalent synchronization primitive.

4. **Resource management**: When accessing the native handle, ensure proper reference counting (add ref before use, release after) to prevent use-after-free if the handle is disposed concurrently.