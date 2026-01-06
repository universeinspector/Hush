# Security Summary – Hush

(the short version for humans)

This is the friendly, honest, no-buzzword summary of Hush’s security model.

If you want the serious version: see SECURITY.md.
If you want the really short version: don’t do dumb things.

# What Hush actually protects

## Hush does protect you against:

- People watching the network

- Malicious relays

- Traffic inspection

- Message tampering

- Accidental plaintext leaks

- Cryptographic regret at 3am (maybe?)

## Your messages are:

- encrypted

- authenticated

- sent over Tor

- boring (in a good way)

## What Hush absolutely does NOT protect you from

Hush cannot protect you against:

- Someone looking at your screen

- Malware, keyloggers, or a compromised system

- Social engineering

- You trusting the wrong person

- You copy-pasting secrets into the wrong terminal (dont do this)

### If your device is owned, Hush is also owned.

## Crypto (very short explanation)

### Hush uses:

- X25519 for key exchange

- HKDF-SHA256 for key derivation

- AES-256-GCM for encryption

#### This means:

- modern

- well-studied

- no DIY crypto

- no clever tricks

- no excitement (which is good)

If this sounds boring, congratulations — that’s correct crypto.

## About Tor

### Tor gives you:

- network-level anonymity

- traffic routing through multiple relays

### Hush gives you:

- end-to-end encrypted messages

- integrity and authenticity

Hush does not magically make Tor better.
Tor does not magically fix bad crypto.

They work together, not instead of each other.

## Authentication (or lack thereof)

Hush does not verify identities.

There is:

- no login

- no usernames

- no trust system

- no key verification

You get a secure channel, not proof of who is on the other end.

If you need identity guarantees, build them on top or wait when I need to procrastinate more and I build it, but probs not

## Memory safety (quick and honest)

#### Go version: tries really hard (secure memory, zeroization)

#### Python version: does its best, but Python is Python

If memory attacks are part of your threat model:
    #### Use the Go version.####

## Legal & ethical use (yes, really)

### Hush is meant for:

- privacy

- learning

- research

- lawful communication

### Hush is not meant for:

- crime

- harassment

- evading law enforcement for illegal stuff

- being a terrible person

Encryption is a tool, not a get-out-of-jail-free card.

## Final advice

Read the code

Understand your threat model

Assume attackers are smarter than you, they probably are

Assume users (including you) will make mistakes

Hush is secure.
It is not magical.
It will not save you from yourself.
