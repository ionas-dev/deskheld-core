# deskheld

## Troubleshooting

### mDNS Service Not Found with MacOS Host

To enable a program using this library to be discoverable via mDNS on a MacOS host, you need to enable System Settings > Privacy & Security > Local Network. This is required for the mDNS service to function properly and allow other devices on the local network to discover the program.

## UniFFI wrapper crate

This workspace includes a UniFFI wrapper crate at `ffi/` (`deskheld-ffi`) for Swift integration.

The wrapper mirrors the currently exposed `client` and `server` API names (`Client::new`, `Client::find_server`, `Client::connect_to`, `Server::new`, `Server::open`, `Server::close`, `Server::publish_service`) and adds Swift-usable receiver objects to consume stream-like outputs (`ResolvedServiceReceiver::recv`, `ConnectionReceiver::recv`).
