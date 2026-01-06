#!/usr/bin/env python3
"""
OnionTalk (Python Port)

This file is a fully interoperable port of the Go implementation.

Cryptographic design:
- X25519 (ECDH) for key exchange
- HKDF-SHA256 for key derivation
- AES-256-GCM for authenticated encryption
- Directional key separation (c2s / s2c)
- Length-prefixed framing over TCP

Protocol compatibility:
Python <-> Go communication is byte-for-byte compatible.
"""

import argparse
import os
import signal
import socket
import struct
import sys
import threading
from dataclasses import dataclass
from typing import Tuple

import socks  # PySocks (SOCKS5 support for Tor)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes



# Network & protocol constants (must match Go implementation)


DEFAULT_PORT = 8001

# Tor SOCKS5 proxy (same defaults as oniontalk.go)
TOR_PROXY_HOST = "127.0.0.1"
TOR_PROXY_PORT = 9050

# framing.go
LEN_PREFIX_SIZE = 4          # uint32 length prefix
NONCE_SIZE = 12              # AES-GCM standard nonce size
MAX_FRAME_SIZE = 1 << 20     # 1 MiB upper bound

# kdf.go
PROTOCOL_INFO = "oniontalk-v1"



# Single-client gate (equivalent to clientConnected + mutex in Go)


_client_connected = False
_client_lock = threading.Lock()


# CLI helpers


def print_help(prog: str) -> None:
    """Prints the same help text as the Go version."""
    print("OnionTalk - Secure talk sessions over Tor\n")
    print("Usage:")
    print("  Listener mode:")
    print(f"    {prog}\n")
    print("  Send mode:")
    print(f"    {prog} -s <onion-address>\n")
    print("Talk Commands:")
    print("  .MULTI  - Start multi-line input")
    print("  .END    - Finish multi-line input")
    print("  .QUIT   - Exit the program")


def parse_host_port(s: str) -> Tuple[str, int]:
    """
    Parses host[:port].

    Onion addresses usually omit the port.
    IPv6 is supported using [addr]:port syntax.
    """
    if s.startswith("[") and "]" in s:
        if "]:" in s:
            host, port = s[1:].split("]:", 1)
            return host, int(port)
        return s[1:-1], DEFAULT_PORT

    if ":" in s and s.count(":") == 1:
        host, port = s.split(":", 1)
        return host, int(port)

    return s, DEFAULT_PORT


def enforce_port(host: str, port: int) -> Tuple[str, int]:
    """
    Enforces the fixed protocol port (8001).

    This mirrors the explicit restriction in the Go code
    and prevents accidental cross-protocol misuse.
    """
    if port != DEFAULT_PORT:
        raise SystemExit(
            f"Error: Only port {DEFAULT_PORT} is allowed. "
            f"Use: program -s {host}:{DEFAULT_PORT}"
        )
    return host, port



# Framing (bit-compatible with framing.go)

def read_exact(sock: socket.socket, n: int) -> bytes:
    """
    Reads exactly n bytes from the socket.

    Equivalent to io.ReadFull in Go.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def write_all(sock: socket.socket, data: bytes) -> None:
    """
    Writes the full buffer to the socket, handling partial sends.
    """
    view = memoryview(data)
    sent = 0
    while sent < len(data):
        n = sock.send(view[sent:])
        if n <= 0:
            raise ConnectionError("connection closed during send")
        sent += n


def write_frame(sock: socket.socket, payload: bytes) -> None:
    """
    Writes a single frame:
      - 4-byte big-endian length prefix
      - payload (must be non-empty)
      - payload size capped at 1 MiB

    Matches framing.go exactly.
    """
    if len(payload) == 0:
        raise ValueError("empty payload")
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError(f"payload too large: {len(payload)}")

    header = struct.pack(">I", len(payload))
    write_all(sock, header)
    write_all(sock, payload)


def read_frame(sock: socket.socket) -> bytes:
    """
    Reads a single framed message and validates size constraints.
    """
    header = read_exact(sock, LEN_PREFIX_SIZE)
    (n,) = struct.unpack(">I", header)

    if n == 0 or n > MAX_FRAME_SIZE:
        raise ValueError(f"invalid frame size: {n}")

    return read_exact(sock, n)



# Key derivation (bit-compatible with kdf.go)


def derive_key(shared_secret: bytes, info: str) -> bytes:
    """
    HKDF-SHA256 key derivation.

    Parameters:
    - shared_secret: X25519 ECDH output
    - salt: None (nil in Go)
    - info: protocol context string

    Output:
    - 32 bytes (AES-256 key)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info.encode("utf-8"),
    )
    return hkdf.derive(shared_secret)


def derive_directional_keys(shared_secret: bytes) -> Tuple[bytes, bytes]:
    """
    Derives two independent keys for directional encryption:

    c2s: client -> server
    s2c: server -> client
    """
    c2s = derive_key(shared_secret, f"{PROTOCOL_INFO}|c2s")
    s2c = derive_key(shared_secret, f"{PROTOCOL_INFO}|s2c")
    return c2s, s2c


# Session key container


@dataclass
class SessionKeys:
    """
    Explicit separation between sending and receiving keys.
    """
    send_key: bytes
    recv_key: bytes



# X25519 key exchange


def perform_key_exchange(conn: socket.socket, is_server: bool) -> SessionKeys:
    """
    Performs the X25519 key exchange.

    Server:
      1. Receives client public key
      2. Sends server public key
      3. Computes shared secret

    Client:
      1. Sends client public key
      2. Receives server public key
      3. Computes shared secret
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()

    if is_server:
        client_pub = read_exact(conn, 32)
        write_all(conn, public_bytes)
        peer = x25519.X25519PublicKey.from_public_bytes(client_pub)
    else:
        write_all(conn, public_bytes)
        server_pub = read_exact(conn, 32)
        peer = x25519.X25519PublicKey.from_public_bytes(server_pub)

    shared_secret = private_key.exchange(peer)
    c2s, s2c = derive_directional_keys(shared_secret)

    # Directional key assignment must match Go logic
    if is_server:
        return SessionKeys(send_key=s2c, recv_key=c2s)
    else:
        return SessionKeys(send_key=c2s, recv_key=s2c)



# Encrypted messaging


def send_encrypted(conn: socket.socket, aead: AESGCM, msg: str) -> None:
    """
    Encrypts and sends a single message.

    Layout:
      frame = nonce || ciphertext
    """
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aead.encrypt(nonce, msg.encode("utf-8"), None)
    write_frame(conn, nonce + ciphertext)
