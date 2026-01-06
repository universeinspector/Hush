# Security Policy – Hush

This document describes the security goals, threat model, and limitations of Hush.
Please read it before assuming anything heroic.

Supported Versions: 
Component	Status
Go implementation	            Supported
Python implementation	        Supported
Modified protocol versions	    Not supported

Only versions that preserve the cryptographic design and protocol compatibility are considered supported.

## Threat Model

### Hush is designed to protect against:

Passive network surveillance

Malicious or compromised relays

Traffic inspection at the transport layer

Message tampering or forgery

Accidental plaintext transmission

Cryptographic downgrade attempts

### Hush is not designed to protect against:

Compromised endpoints

Malware, keyloggers, or screen capture

Physical access to the device

Social engineering

Operational security mistakes

Users trusting the wrong people

If your device is compromised, Hush cannot help you.

## Cryptographic Design

### Key Exchange

Algorithm: X25519 (ECDH)

Key type: Ephemeral

Property: Forward secrecy

Each session uses fresh keys.
No long-term secrets are reused.

### Key Derivation

KDF: HKDF with SHA-256

Salt: nil

Info strings:

oniontalk-v1|c2s

oniontalk-v1|s2c

Output: 32 bytes per key (AES-256)

### Directional key separation ensures:

Keys are never reused across directions

Reflection and key-reuse attacks are avoided

Compromise of one direction does not affect the other

Symmetric Encryption

Algorithm: AES-256-GCM

Nonce size: 12 bytes

Nonce source: Cryptographically secure randomness

Authentication: Built-in (AEAD)

If decryption or authentication fails, the connection is terminated immediately.

There is no fallback, no recovery mode, and no silent failure.

### Transport Security
Framing

Length-prefixed frames (uint32, big-endian)

Maximum frame size: 1 MiB

Empty frames are rejected

This prevents:

Message boundary confusion

Truncation attacks

Memory exhaustion attacks

Directional Encryption

Each direction uses a different key:

Direction	Key
Client → Server	c2s
Server → Client	s2c

Keys are never reused between sessions or directions.

# Tor Integration

Hush is designed to run over Tor

A SOCKS5 proxy is expected to be available

Hush does not attempt to bypass Tor

Hush does not claim to anonymize traffic by itself

## Tor provides:

Network-level anonymity

Path obfuscation

Hush provides:

End-to-end encryption

Message authenticity

### They solve different problems and are meant to be used together.

### Authentication

Hush does not provide identity authentication.

#### There is:

no identity verification

no key pinning

no trust establishment

This is intentional.

Hush provides a secure channel, not identity guarantees.
If authentication is required, it must be implemented on top of the protocol.

# Memory Safety
## Go implementation

Uses memguard for sensitive data

Explicit zeroization

Stronger guarantees

## Python implementation

Best-effort only

Python’s garbage collector and immutable objects prevent reliable zeroization

If memory scraping is part of your threat model:
Use the Go implementation.

# Legal & Ethical Use

Hush is intended only for lawful and ethical purposes, including:

-private communication

-research and education

-learning about cryptography

-protecting personal privacy

You must not use this software to:

-facilitate criminal activity

-distribute illegal content

-evade law enforcement for illegal purposes

-harass, threaten, or harm others

The authors and contributors do not endorse and are not responsible for any illegal or malicious use of this software.

Encryption is a tool — not a shield against accountability.

## Known Limitations

No replay protection beyond AEAD guarantees

No traffic padding

No resistance to timing analysis

No plausible deniability claims

No protection against compromised endpoints

This is a secure channel — not a magic invisibility cloak.

## Reporting Security Issues

If you believe you have found a security vulnerability:

Do not open a public issue

Provide a clear description of the issue

Include steps to reproduce if possible

State the threat model you are assuming

Low-effort reports without technical detail may be ignored.

## Security Philosophy

Small attack surface

Boring, well-studied primitives

Explicit design decisions

No “clever” cryptography

No crypto agility

No DIY crypto

If it feels exciting, it is probably wrong.

# Final Note

Hush is designed to be secure by design,
but no software can protect users from:

compromised systems

unrealistic threat models

incorrect assumptions

Read the code.
Understand the limitations.
Use responsibly.
