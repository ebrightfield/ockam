
use anyhow::anyhow;
use ockam_api::config::lookup::InternetAddress;

/// Validates a TCP address, and returns the String.
/// NOTE: Not keeping the `InternetAddress` type here because
/// there are downstream complications that start to get less straightforward,
/// starting here:
/// implementations/rust/ockam/ockam_api/src/nodes/service/transport.rs:35
///
/// There's a cbor `Decode` trait that would need to be added to the `InternetAddress` type,
/// and a few other changes, e.g. the `TcpTransport` takes `S: AsRef<str>`,
/// which is not easily possible because `InternetAddress` doesn't have its own owned string data
/// to which it can expose a reference.
pub fn parse_tcp_addr(addr: &str) -> anyhow::Result<String> {
    InternetAddress::new(addr)
        .map(|_| addr.to_string())
        .ok_or(anyhow!("Not a valid TCP address"))
}

