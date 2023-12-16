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
    rt::{
        TokioIo,
    },
};

use crate::{
    proxy,
    resolver,
    Io,
    IoKind,
    IoTcp,
};

#[derive(Debug)]
pub enum Error {
    UriMissingScheme {
        uri: Uri,
    },
    UriMissingHost {
        uri: Uri,
    },
    ResolverBuild(hickory_resolver::error::ResolveError),
    Connection(Box<dyn std::error::Error>),
    ConnectionToSocks5(Box<dyn std::error::Error>),
    ConnectionViaSocks5(async_socks5::Error),
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
    pub fn connection_setup(self, uri: Uri) -> Result<ConnectionBuilder, Error> {
        if uri.scheme().is_none() {
            return Err(Error::UriMissingScheme { uri, });
        }
        let uri_host = uri.host()
            .ok_or_else(|| Error::UriMissingHost { uri: uri.clone(), })?
            .to_string();
        let resolver = resolver::HickoryResolver::new(self.resolver_kind)
            .map_err(Error::ResolverBuild)?;
        Ok(ConnectionBuilder::new(resolver, uri, uri_host))
    }
}

pub struct ConnectionBuilder {
    uri: Uri,
    uri_host: String,
    http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
}

impl ConnectionBuilder {
    fn new(resolver: resolver::HickoryResolver, uri: Uri, uri_host: String) -> Self {
        Self {
            uri,
            uri_host,
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

    /// Build and establish connection
    pub async fn establish(mut self) -> Result<Io, Error> {
        let stream =
            tower_service::Service::call(
                &mut self.http_connector,
                self.uri,
            )
            .await
            .map_err(|error| {
                Error::Connection(Box::new(error) as Box<dyn std::error::Error>)
            })?;

        Ok(Io {
            kind: IoKind::Tcp(
                IoTcp {
                    stream,
                },
            ),
        })
    }

    /// Build connection and proceed with tls setup.
    pub fn tls_setup(self) -> TlsBuilder {
        TlsBuilder::new(
            proxy::ProxyKind::None,
            self.http_connector,
            self.uri,
            self.uri_host,
        )
    }

    /// Build connection and proceed with socks5 proxy setup.
    pub fn socks5_proxy_setup(self, proxy_addr: Uri) -> Socks5ProxyBuilder {
        Socks5ProxyBuilder::new(
            proxy_addr,
            self.http_connector,
            self.uri,
            self.uri_host,
        )
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Socks5Auth {
    pub username: String,
    pub password: String,
}

impl From<async_socks5::Auth> for Socks5Auth {
    fn from(auth: async_socks5::Auth) -> Self {
        Self {
            username: auth.username,
            password: auth.password,
        }
    }
}

impl From<Socks5Auth> for async_socks5::Auth {
    fn from(auth: Socks5Auth) -> Self {
        async_socks5::Auth::new(auth.username, auth.password)
    }
}

pub struct Socks5ProxyBuilder {
    uri: Uri,
    uri_host: String,
    http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
    proxy_addr: Uri,
    proxy_auth: Option<Socks5Auth>,
}

impl Socks5ProxyBuilder {
    fn new(
        proxy_addr: Uri,
        http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
        uri: Uri,
        uri_host: String,
    )
        -> Self
    {
        Self {
            uri,
            uri_host,
            http_connector,
            proxy_addr,
            proxy_auth: None,
        }
    }

    /// Configure a username + password authentication for the proxy.
    ///
    /// If `None`, no authentication is performed.
    ///
    /// Default is `None`.
    pub fn auth(mut self, proxy_auth: Option<Socks5Auth>) -> Self {
        self.proxy_auth = proxy_auth;
        self
    }

    /// Build and establish connection
    pub async fn establish(mut self) -> Result<Io, Error> {
        let port = match self.uri.port() {
            Some(port) =>
                port.as_u16(),
            None =>
                if self.uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
                    443
                } else {
                    80
                },
        };
        let target_addr =
            async_socks5::AddrKind::Domain(self.uri_host, port);

        let tokio_io_stream =
            tower_service::Service::call(
                &mut self.http_connector,
                self.proxy_addr,
            )
            .await
            .map_err(|error| {
                Error::ConnectionToSocks5(Box::new(error) as Box<dyn std::error::Error>)
            })?;
        let stream = tokio_io_stream
            .into_inner();

        let mut buf_stream =
            tokio::io::BufStream::new(stream);
        let _addr_kind =
            async_socks5::connect(
                &mut buf_stream,
                target_addr,
                self.proxy_auth.map(Into::into),
            )
            .await
            .map_err(Error::ConnectionViaSocks5)?;
        Ok(Io {
            kind: IoKind::Tcp(
                IoTcp {
                    stream: TokioIo::new(
                        buf_stream.into_inner(),
                    ),
                },
            ),
        })
    }
}

pub struct TlsBuilder {
    uri: Uri,
    uri_host: String,
    http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
    proxy_kind: proxy::ProxyKind,
}

impl TlsBuilder {
    fn new(
        proxy_kind: proxy::ProxyKind,
        http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
        uri: Uri,
        uri_host: String,
    )
        -> Self
    {
        Self {
            uri,
            uri_host,
            http_connector,
            proxy_kind,
        }
    }
}
