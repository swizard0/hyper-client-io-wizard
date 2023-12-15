use std::{
    time::{
        Duration,
    },
    net::{
        IpAddr,
        Ipv4Addr,
        Ipv6Addr,
        SocketAddr,
    },
};

use http::{
    uri::{
        Uri,
    },
};

mod tcp_keepalive;

pub struct IoBuilder {
    uri: Uri,
    enforce_http: bool,
    connect_timeout: Option<Duration>,
    happy_eyeballs_timeout: Option<Duration>,
    tcp_keepalive_config: tcp_keepalive::TcpKeepaliveConfig,
    local_address_ipv4: Option<Ipv4Addr>,
    local_address_ipv6: Option<Ipv6Addr>,
    nodelay: bool,
    reuse_address: bool,
    send_buffer_size: Option<usize>,
    recv_buffer_size: Option<usize>,
    interface: Option<String>,
}

impl IoBuilder {
    pub(super) fn new(uri: Uri) -> Self {
        Self {
            uri,
            enforce_http: false,
            connect_timeout: None,
            happy_eyeballs_timeout: None,
            tcp_keepalive_config: tcp_keepalive::TcpKeepaliveConfig::default(),
            local_address_ipv4: None,
            local_address_ipv6: None,
            nodelay: false,
            reuse_address: false,
            send_buffer_size: None,
            recv_buffer_size: None,
            interface: None,
        }
    }

    /// Set that all sockets have `SO_KEEPALIVE` set with the supplied duration
    /// to remain idle before sending TCP keepalive probes.
    ///
    /// If `None`, keepalive is disabled.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_keepalive(&mut self, time: Option<Duration>) {
        self.tcp_keepalive_config.time = time;
    }

    /// Set the duration between two successive TCP keepalive retransmissions,
    /// if acknowledgement to the previous keepalive transmission is not received.
    #[inline]
    pub fn set_keepalive_interval(&mut self, interval: Option<Duration>) {
        self.tcp_keepalive_config.interval = interval;
    }

    /// Set the number of retransmissions to be carried out before declaring that remote end is not available.
    #[inline]
    pub fn set_keepalive_retries(&mut self, retries: Option<u32>) {
        self.tcp_keepalive_config.retries = retries;
    }

    /// Set that all sockets have `SO_NODELAY` set to the supplied value `nodelay`.
    ///
    /// Default is `false`.
    #[inline]
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    /// Sets the value of the SO_SNDBUF option on the socket.
    #[inline]
    pub fn set_send_buffer_size(&mut self, size: Option<usize>) {
        self.send_buffer_size = size;
    }

    /// Sets the value of the SO_RCVBUF option on the socket.
    #[inline]
    pub fn set_recv_buffer_size(&mut self, size: Option<usize>) {
        self.recv_buffer_size = size;
    }

    /// Set that all sockets are bound to the configured address before connection.
    ///
    /// If `None`, the sockets will not be bound.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_local_address(&mut self, addr: Option<IpAddr>) {
        let (v4, v6) = match addr {
            Some(IpAddr::V4(a)) => (Some(a), None),
            Some(IpAddr::V6(a)) => (None, Some(a)),
            _ => (None, None),
        };

        let cfg = self;

        cfg.local_address_ipv4 = v4;
        cfg.local_address_ipv6 = v6;
    }

    /// Set that all sockets are bound to the configured IPv4 or IPv6 address (depending on host's
    /// preferences) before connection.
    #[inline]
    pub fn set_local_addresses(&mut self, addr_ipv4: Ipv4Addr, addr_ipv6: Ipv6Addr) {
        let cfg = self;

        cfg.local_address_ipv4 = Some(addr_ipv4);
        cfg.local_address_ipv6 = Some(addr_ipv6);
    }

    /// Set the connect timeout.
    ///
    /// If a domain resolves to multiple IP addresses, the timeout will be
    /// evenly divided across them.
    ///
    /// Default is `None`.
    #[inline]
    pub fn set_connect_timeout(&mut self, dur: Option<Duration>) {
        self.connect_timeout = dur;
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
    #[inline]
    pub fn set_happy_eyeballs_timeout(&mut self, dur: Option<Duration>) {
        self.happy_eyeballs_timeout = dur;
    }

    /// Set that all socket have `SO_REUSEADDR` set to the supplied value `reuse_address`.
    ///
    /// Default is `false`.
    #[inline]
    pub fn set_reuse_address(&mut self, reuse_address: bool) -> &mut Self {
        self.reuse_address = reuse_address;
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
    #[inline]
    pub fn set_interface<S: Into<String>>(&mut self, interface: S) -> &mut Self {
        self.interface = Some(interface.into());
        self
    }
}
