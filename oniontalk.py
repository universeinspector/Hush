#!/usr/bin/env python3
"""
OnionTalk (Python Port)

Dieses Programm ist eine 1:1 kompatible Portierung der Go-Version:
- X25519 Key Exchange
- HKDF-SHA256 Key Derivation (oniontalk-v1|c2s / |s2c)
- AES-256-GCM mit zufälligem Nonce
- Frame-basiertes TCP-Protokoll (uint32 Big Endian)
- Tor SOCKS5 Dialer
- Interaktive Chat-Kommandos (.MULTI / .END / .QUIT)

Ziel:
Python-Client <-> Go-Server
Python-Server <-> Go-Client
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

import socks  # PySocks – notwendig für Tor SOCKS5
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------
# Netz & Protokoll-Konstanten (identisch zu Go)
# ---------------------------------------------------------------------------

DEFAULT_PORT = 8001

# Tor SOCKS5 Proxy (wie in oniontalk.go)
TOR_PROXY_HOST = "127.0.0.1"
TOR_PROXY_PORT = 9050

# framing.go
LEN_PREFIX_SIZE = 4          # uint32
NONCE_SIZE = 12              # AES-GCM Standard
MAX_FRAME_SIZE = 1 << 20     # 1 MiB

# kdf.go
PROTOCOL_INFO = "oniontalk-v1"

# ---------------------------------------------------------------------------
# Single-Client-Gate (entspricht clientConnected + Mutex in Go)
# ---------------------------------------------------------------------------

_client_connected = False
_client_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Hilfsfunktionen: CLI / Parsing
# ---------------------------------------------------------------------------

def print_help(prog: str) -> None:
    """Gibt exakt dieselbe Hilfe aus wie die Go-Version."""
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
    Akzeptiert:
      - host
      - host:port
      - [ipv6]:port

    Onion-Adressen kommen üblicherweise ohne Port.
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
    Erzwingt Port 8001 – exakt wie im Go-Code.
    """
    if port != DEFAULT_PORT:
        raise SystemExit(
            f"Error: Only port {DEFAULT_PORT} is allowed. "
            f"Use: program -s {host}:{DEFAULT_PORT}"
        )
    return host, port


# ---------------------------------------------------------------------------
# Framing (bitgenau zu framing.go)
# ---------------------------------------------------------------------------

def read_exact(sock: socket.socket, n: int) -> bytes:
    """
    Liest exakt n Bytes vom Socket.
    Entspricht io.ReadFull in Go.
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
    Schreibt alle Bytes zuverlässig.
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
    framing.go:
      - payload darf nicht leer sein
      - max 1 MiB
      - uint32 Big Endian Längenpräfix
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
    framing.go:
      - liest 4 Byte Länge
      - prüft 0 < n <= 1 MiB
    """
    header = read_exact(sock, LEN_PREFIX_SIZE)
    (n,) = struct.unpack(">I", header)

    if n == 0 or n > MAX_FRAME_SIZE:
        raise ValueError(f"invalid frame size: {n}")

    return read_exact(sock, n)


# ---------------------------------------------------------------------------
# KDF (bitgenau zu kdf.go)
# ---------------------------------------------------------------------------

def derive_key(shared_secret: bytes, info: str) -> bytes:
    """
    HKDF-SHA256
    - salt = nil
    - info = oniontalk-v1|{c2s,s2c}
    - output = 32 Bytes (AES-256)
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
    Liefert zwei unabhängige Richtungskeys:
      - c2s = client -> server
      - s2c = server -> client
    """
    c2s = derive_key(shared_secret, f"{PROTOCOL_INFO}|c2s")
    s2c = derive_key(shared_secret, f"{PROTOCOL_INFO}|s2c")
    return c2s, s2c


# ---------------------------------------------------------------------------
# Session Keys (klar getrennt Send/Recv)
# ---------------------------------------------------------------------------

@dataclass
class SessionKeys:
    send_key: bytes
    recv_key: bytes


# ---------------------------------------------------------------------------
# Key Exchange (X25519)
# ---------------------------------------------------------------------------

def perform_key_exchange(conn: socket.socket, is_server: bool) -> SessionKeys:
    """
    Ablauf exakt wie in oniontalk.go:

    Server:
      1. liest Client-Pubkey
      2. sendet eigenen Pubkey
      3. berechnet Shared Secret

    Client:
      1. sendet eigenen Pubkey
      2. liest Server-Pubkey
      3. berechnet Shared Secret
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

    # Key-Separation identisch zur Go-Version
    if is_server:
        return SessionKeys(send_key=s2c, recv_key=c2s)
    else:
        return SessionKeys(send_key=c2s, recv_key=s2c)


# ---------------------------------------------------------------------------
# Verschlüsselte Kommunikation
# ---------------------------------------------------------------------------

def send_encrypted(conn: socket.socket, aead: AESGCM, msg: str) -> None:
    """
    - erzeugt zufälligen Nonce
    - AES-GCM encrypt
    - nonce || ciphertext als Frame
    """
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aead.encrypt(nonce, msg.encode("utf-8"), None)
    write_frame(conn, nonce + ciphertext)
