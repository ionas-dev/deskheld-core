# deskheld

## Swift Bindings

Generate UniFFI Swift bindings for `common`, `server`, and `client` into `target/swift`:

```bash
./scripts/generate-swift-bindings.sh
```

This produces:
- `target/swift/common`
- `target/swift/server`
- `target/swift/client`

## Logging

Rust logging is initialized automatically by the library when creating a `Server` or `Client`,
but only if `RUST_LOG` is set.

Examples:

```bash
RUST_LOG=debug
RUST_LOG=server=debug,client=debug,mdns_sd=debug
```

In Xcode, set `RUST_LOG` in `Edit Scheme > Run > Arguments > Environment Variables`.
No Swift-side logger initialization call is required.

## Async Runtime

The library creates and reuses an internal Tokio runtime on first use.
Swift callers do not need to create or manage a Tokio runtime.

## Troubleshooting

### mDNS Service Not Found with macOS Host

To enable a program using this library to be discoverable via mDNS on a macOS host, you need to enable System Settings > Privacy & Security > Local Network. This is required for the mDNS service to function properly and allow other devices on the local network to discover the program.
