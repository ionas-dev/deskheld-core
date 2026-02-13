# client

Deskheld QUIC client crate with mDNS-based server discovery.

## What it contains

- `Client`: creates a QUIC client endpoint with local identity and TLS config.
- Discovery: `find_server()` to browse `_deskheld._udp.local.` services.
- Connection flow: `connect_to()` plus trust classification from `common::connection`.
- `Service` and `ServiceReceiver`: UniFFI-safe discovery records/receiver object.

## UniFFI notes

- `find_server_ffi()` is exported as `findServer` for bindings.
- `SocketAddr` is bridged as a UniFFI custom type through string lift/lower.
