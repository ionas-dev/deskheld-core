# server

Deskheld QUIC server crate with mDNS publication.

## What it contains

- `Server`: creates a QUIC server endpoint and manages mDNS publication lifecycle.
- Accept loop: `open()` returns a receiver of classified incoming connections.
- `ConnectionReceiver`: UniFFI-safe async wrapper around incoming connection channel.
- Demo binaries/examples for manual local testing.

## UniFFI notes

- `open_ffi()` is exported as `open` for bindings.
- `SocketAddr` is bridged as a UniFFI custom type through string lift/lower.
