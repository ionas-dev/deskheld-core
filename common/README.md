# common

Shared Deskheld primitives used by `client` and `server`.

## What it contains

- `certificate`: local identity generation/loading and trusted-device persistence.
- `config`: shared names, addresses, ALPN, mDNS service type, and config-dir lookup.
- `connection`: trust classification (`Accepted` vs `Quarantined`) and connection wrappers.
- Runtime helpers: one-time rustls provider/logger init and a shared Tokio runtime.

## UniFFI notes

This crate declares shared UniFFI-compatible types (`Connection`, `AcceptedConnection`, `QuarantineConnection`) and exposes wrapper methods for binding-friendly names where needed.
