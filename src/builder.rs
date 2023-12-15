use std::{
    time::{
        Duration,
    },
    net::{
        IpAddr,
        Ipv4Addr,
        Ipv6Addr,
    },
};

use http::{
    uri::{
        Uri,
    },
};

use hyper_util::{
    client::{
        legacy,
    },
};

use crate::{
    resolver,
};

#[derive(Debug)]
pub enum Error {
    ResolverBuild(hickory_resolver::error::ResolveError),
}

pub struct ResolverBuilder {
    resolver_kind: resolver::ResolverKind,
}

impl ResolverBuilder {
    pub(super) fn new() -> Self {
        Self {
            resolver_kind: resolver::ResolverKind::System,
        }
    }

    /// Creates a system configuration.
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    ///
    /// Default resolver is `system`.
    pub fn system(mut self) -> Self {
        self.resolver_kind = resolver::ResolverKind::System;
        self
    }

    /// Creates a configuration using 8.8.8.8, 8.8.4.4 and 2001:4860:4860::8888, 2001:4860:4860::8844.
    ///
    /// Default resolver is `system`.
    pub fn google(mut self) -> Self {
        self.resolver_kind = resolver::ResolverKind::Google;
        self
    }

    /// Creates a configuration using 8.8.8.8, 8.8.4.4 and 2001:4860:4860::8888, 2001:4860:4860::8844.
    /// This limits the registered connections to just TLS lookups.
    ///
    /// Default resolver is `system`.
    pub fn google_tls(mut self) -> Self {
        self.resolver_kind = resolver::ResolverKind::GoogleTls;
        self
    }

    /// Creates a configuration using 8.8.8.8, 8.8.4.4 and 2001:4860:4860::8888, 2001:4860:4860::8844.
    /// This limits the registered connections to just HTTPS lookups.
    ///
    /// Default resolver is `system`.
    pub fn google_https(mut self) -> Self {
        self.resolver_kind = resolver::ResolverKind::GoogleHttps;
        self
    }

    /// Build resolver and proceed with connection setup.
    pub fn connection_setup(self, uri: Uri) -> Result<IoBuilder, Error> {
        let resolver = resolver::HickoryResolver::new(self.resolver_kind)
            .map_err(Error::ResolverBuild)?;
        Ok(IoBuilder::new(resolver, uri))
    }
}

pub struct IoBuilder {
    uri: Uri,
    http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
}

impl IoBuilder {
    fn new(resolver: resolver::HickoryResolver, uri: Uri) -> Self {
        Self {
            uri,
            http_connector: legacy::connect::HttpConnector::new_with_resolver(resolver),
        }
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied duration
    /// to remain idle before sending TCP keepalive probes.
    ///
    /// If `None`, keepalive is disabled.
    ///
    /// Default is `None`.
    pub fn keepalive(mut self, time: Option<Duration>) -> Self {
        self.http_connector.set_keepalive(time);
        self
    }

    /// Set the duration between two successive TCP keepalive retransmissions,
    /// if acknowledgement to the previous keepalive transmission is not received.
    pub fn keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.http_connector.set_keepalive_interval(interval);
        self
    }

    /// Set the number of retransmissions to be carried out before declaring that remote end is not available.
    pub fn keepalive_retries(mut self, retries: Option<u32>) -> Self {
        self.http_connector.set_keepalive_retries(retries);
        self
    }

    /// Set that all sockets have `SO_NODELAY` set to the supplied value `nodelay`.
    ///
    /// Default is `false`.
    pub fn nodelay(mut self, nodelay: bool) -> Self {
        self.http_connector.set_nodelay(nodelay);
        self
    }

    /// Sets the value of the SO_SNDBUF option on the socket.
    pub fn send_buffer_size(mut self, size: Option<usize>) -> Self {
        self.http_connector.set_send_buffer_size(size);
        self
    }

    /// Sets the value of the SO_RCVBUF option on the socket.
    pub fn recv_buffer_size(mut self, size: Option<usize>) -> Self {
        self.http_connector.set_recv_buffer_size(size);
        self
    }

    /// Set that all sockets are bound to the configured address before connection.
    ///
    /// If `None`, the sockets will not be bound.
    ///
    /// Default is `None`.
    pub fn local_address(mut self, addr: Option<IpAddr>) -> Self {
        self.http_connector.set_local_address(addr);
        self
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    pub fn local_addresses(mut self, addr_ipv4: Ipv4Addr, addr_ipv6: Ipv6Addr) -> Self {
        self.http_connector.set_local_addresses(addr_ipv4, addr_ipv6);
        self
    }

    /// Set the connect timeout.
    ///
    /// If a domain resolves to multiple IP addresses, the timeout will be
    /// evenly divided across them.
    ///
    /// Default is `None`.
    pub fn connect_timeout(mut self, dur: Option<Duration>) -> Self {
        self.http_connector.set_connect_timeout(dur);
        self
    }

    /// Set timeout for [RFC 6555 (Happy Eyeballs)][RFC 6555] algorithm.
    ///
    /// If hostname resolves to both IPv4 and IPv6 addresses and connection
    /// cannot be established using preferred address family before timeout
    /// elapses, then connector will in parallel attempt connection using other
    /// address family.
    ///
    /// If `None`, parallel connection attempts are disabled.
    ///
    /// Default is 300 milliseconds.
    ///
    /// [RFC 6555]: https://tools.ietf.org/html/rfc6555
    pub fn happy_eyeballs_timeout(mut self, dur: Option<Duration>) -> Self {
        self.http_connector.set_happy_eyeballs_timeout(dur);
        self
    }

    /// Set that all socket have `SO_REUSEADDR` set to the supplied value `reuse_address`.
    ///
    /// Default is `false`.
    pub fn reuse_address(mut self, reuse_address: bool) -> Self {
        self.http_connector.set_reuse_address(reuse_address);
        self
    }

    /// Sets the value for the `SO_BINDTODEVICE` option on this socket.
    ///
    /// If a socket is bound to an interface, only packets received from that particular
    /// interface are processed by the socket. Note that this only works for some socket
    /// types, particularly AF_INET sockets.
    ///
    /// On Linux it can be used to specify a [VRF], but the binary needs
    /// to either have `CAP_NET_RAW` or to be run as root.
    ///
    /// This function is only available on Android、Fuchsia and Linux.
    ///
    /// [VRF]: https://www.kernel.org/doc/Documentation/networking/vrf.txt
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn interface<S: Into<String>>(mut self, interface: S) -> Self {
        self.http_connector.set_interface(interface);
        self
    }
}
