# deskheld

## Workspace

- `common`: shared certificate, configuration, connection, and runtime utilities. See `common/README.md`.
- `client`: QUIC client with mDNS discovery and UniFFI exports. See `client/README.md`.
- `server`: QUIC server with mDNS publication and UniFFI exports. See `server/README.md`.
- `uniffi-bindgen`: helper CLI crate for running UniFFI bindgen. See `uniffi-bindgen/README.md`.

## Swift Bindings

Generate UniFFI Swift bindings for `common`, `server`, and `client` into `target/swift`:

```bash
./scripts/generate-swift-bindings.sh
```

This produces:
- `target/swift/common`
- `target/swift/server`
- `target/swift/client`

## Troubleshooting

### mDNS Service Not Found with macOS Host

To enable a program using this library to be discoverable via mDNS on a macOS host, you need to enable System Settings > Privacy & Security > Local Network. This is required for the mDNS service to function properly and allow other devices on the local network to discover the program.
