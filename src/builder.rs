use std::{
    sync::{
        Arc,
    },
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

use tokio::{
    net::{
        TcpStream,
    },
};


use crate::{
    resolver,
    Io,
    Protocols,
    IoStream,
    IoKind,
    IoTcp,
    IoTcpTls,
    TokioIo,
};

#[derive(Debug)]
pub enum Error {
    UriMissingScheme {
        uri: Uri,
    },
    UriMissingHost {
        uri: Uri,
    },
    UriUnsupportedHttpsScheme {
        uri: Uri,
        scheme: http::uri::Scheme,
    },
    ResolverBuild(hickory_resolver::error::ResolveError),
    TlsNonEmptyAlpnProtocols,
    TlsNativeCertsLoad(std::io::Error),
    TlsNativeCertAdd(rustls::Error),
    TlsInvalidDnsName {
        hostname: String,
        error: rustls::pki_types::InvalidDnsNameError,
    },
    Connection(Box<dyn std::error::Error>),
    ConnectionToSocks5(Box<dyn std::error::Error>),
    ConnectionViaSocks5(async_socks5::Error),
    ConnectionTls(std::io::Error),
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
        let uri_scheme = uri.scheme()
            .ok_or_else(|| Error::UriMissingScheme { uri: uri.clone(), })?
            .clone();
        let uri_host = uri.host()
            .ok_or_else(|| Error::UriMissingHost { uri: uri.clone(), })?
            .to_string();
        let resolver = resolver::HickoryResolver::new(self.resolver_kind)
            .map_err(Error::ResolverBuild)?;
        Ok(ConnectionBuilder::new(resolver, uri, uri_host, uri_scheme))
    }
}

pub struct ConnectionBuilder {
    uri: Uri,
    uri_host: String,
    uri_scheme: http::uri::Scheme,
    http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
}

impl ConnectionBuilder {
    fn new(
        resolver: resolver::HickoryResolver,
        uri: Uri,
        uri_host: String,
        uri_scheme: http::uri::Scheme,
    )
        -> Self
    {
        Self {
            uri,
            uri_host,
            uri_scheme,
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
    pub async fn establish(self) -> Result<Io, Error> {
        let stream = connection_establish_tcp(self.http_connector, self.uri).await?;
        Ok(Io {
            protocols: Protocols {
                http1_support: true,
                http2_support: false,
            },
            uri_host: self.uri_host,
            stream: IoStream {
                kind: IoKind::Tcp(
                    IoTcp {
                        stream,
                    },
                ),
            },
        })
    }

    /// Build connection and proceed with tls setup.
    pub async fn tls_setup(self) -> Result<TlsBuilder, Error> {
        let stream = connection_establish_tcp(self.http_connector, self.uri.clone()).await?;
        Ok(TlsBuilder::new(
            stream,
            self.uri,
            self.uri_host,
            self.uri_scheme,
        ))
    }

    /// Build connection and proceed with socks5 proxy setup.
    pub fn socks5_proxy_setup(self, proxy_addr: Uri) -> Socks5ProxyBuilder {
        Socks5ProxyBuilder::new(
            proxy_addr,
            self.http_connector,
            self.uri,
            self.uri_host,
            self.uri_scheme,
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
    uri_scheme: http::uri::Scheme,
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
        uri_scheme: http::uri::Scheme,
    )
        -> Self
    {
        Self {
            uri,
            uri_host,
            uri_scheme,
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
    pub async fn establish(self) -> Result<Io, Error> {
        let stream =
            connection_establish_proxy(
                self.proxy_addr,
                self.proxy_auth,
                self.http_connector,
                self.uri,
                self.uri_host.clone(),
            )
            .await?;
        Ok(Io {
            protocols: Protocols {
                http1_support: true,
                http2_support: false,
            },
            uri_host: self.uri_host,
            stream: IoStream {
                kind: IoKind::Tcp(
                    IoTcp {
                        stream,
                    },
                ),
            },
        })
    }

    /// Build connection and proceed with tls setup.
    pub async fn tls_setup(self) -> Result<TlsBuilder, Error> {
        let stream =
            connection_establish_proxy(
                self.proxy_addr,
                self.proxy_auth,
                self.http_connector,
                self.uri.clone(),
                self.uri_host.clone(),
            )
            .await?;

        Ok(TlsBuilder::new(
            stream,
            self.uri,
            self.uri_host,
            self.uri_scheme,
        ))
    }
}

pub struct TlsBuilder {
    uri: Uri,
    uri_host: String,
    uri_scheme: http::uri::Scheme,
    stream: TokioIo<TcpStream>,
}

impl TlsBuilder {
    fn new(
        stream: TokioIo<TcpStream>,
        uri: Uri,
        uri_host: String,
        uri_scheme: http::uri::Scheme,
    )
        -> Self
    {
        Self {
            uri,
            uri_host,
            uri_scheme,
            stream,
        }
    }

    /// Passes a rustls [`ClientConfig`] to configure the TLS connection
    ///
    /// The [`alpn_protocols`](ClientConfig::alpn_protocols) field is
    /// required to be empty (or the function will panic) and will be
    /// rewritten to match the enabled schemes (see
    /// [`enable_http1`](TlsBuilderConfig::enable_http1),
    /// [`enable_http2`](TlsBuilderConfig::enable_http2)) before the
    /// connector is built.
    pub fn tls_config(self, config: rustls::ClientConfig) -> Result<TlsBuilderConfig, Error> {
        if !config.alpn_protocols.is_empty() {
            Err(Error::TlsNonEmptyAlpnProtocols)
        } else {
            Ok(TlsBuilderConfig::new(
                config,
                self.stream,
                self.uri,
                self.uri_host,
                self.uri_scheme,
            ))
        }
    }

    /// Shorthand for using rustls safe defaults and native roots
    pub fn native_roots(self) -> Result<TlsBuilderConfig, Error> {
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs_iter = rustls_native_certs::load_native_certs()
            .map_err(Error::TlsNativeCertsLoad)?;
        for cert in native_certs_iter {
            root_store.add(cert)
                .map_err(Error::TlsNativeCertAdd)?;
        }
        Ok(TlsBuilderConfig::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
            self.stream,
            self.uri,
            self.uri_host,
            self.uri_scheme,
        ))
    }

    /// Shorthand for using rustls safe defaults and Mozilla roots
    pub fn webpki_roots(self) -> Result<TlsBuilderConfig, Error> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
        Ok(TlsBuilderConfig::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
            self.stream,
            self.uri,
            self.uri_host,
            self.uri_scheme,
        ))
    }
}

pub struct TlsBuilderConfig {
    uri: Uri,
    uri_host: String,
    uri_scheme: http::uri::Scheme,
    stream: TokioIo<TcpStream>,
    tls_config: rustls::ClientConfig,
    https_only: bool,
    http1_enabled: bool,
    http2_enabled: bool,
    override_server_name: Option<String>,
}

impl TlsBuilderConfig {
    fn new(
        tls_config: rustls::ClientConfig,
        stream: TokioIo<TcpStream>,
        uri: Uri,
        uri_host: String,
        uri_scheme: http::uri::Scheme,
    )
        -> Self
    {
        Self {
            uri,
            uri_host,
            uri_scheme,
            stream,
            tls_config,
            https_only: false,
            http1_enabled: false,
            http2_enabled: false,
            override_server_name: None,
        }
    }

    /// Enforce the use of HTTPS when connecting
    ///
    /// Only URLs using the HTTPS scheme will be connectable.
    ///
    /// Default is `https_or_http`.
    pub fn https_only(mut self) -> Self {
        self.https_only = true;
        self
    }

    /// Allow both HTTPS and HTTP when connecting
    ///
    /// HTTPS URLs will be handled through rustls,
    /// HTTP URLs will be handled directly.
    ///
    /// Default is `https_or_http`.
    pub fn https_or_http(mut self) -> Self {
        self.https_only = false;
        self
    }

    /// Enable HTTP1
    ///
    /// This needs to be called explicitly, no protocol is enabled by default
    pub fn enable_http1(mut self) -> Self {
        self.http1_enabled = true;
        self.http2_enabled = false;
        self
    }

    /// Enable HTTP2
    ///
    /// This needs to be called explicitly, no protocol is enabled by default
    pub fn enable_http2(mut self) -> Self {
        self.http1_enabled = false;
        self.http2_enabled = true;
        self
    }

    /// Enable all HTTP versions
    ///
    /// For now, this enables both HTTP 1 and 2. In the future, other supported versions
    /// will be enabled as well.
    pub fn enable_all_versions(mut self) -> Self {
        self.http1_enabled = true;
        self.http2_enabled = true;
        self
    }

    /// Override server name for the TLS stack
    ///
    /// By default, for each connection the library will extract host portion
    /// of the destination URL and verify that server certificate contains
    /// this value.
    ///
    /// If this method is called, the library will instead verify that server
    /// certificate contains `override_server_name`. Domain name included in
    /// the URL will not affect certificate validation.
    pub fn with_server_name(mut self, override_server_name: String) -> Self {
        self.override_server_name = Some(override_server_name);
        self
    }

    /// Build and establish connection
    pub async fn establish(mut self) -> Result<Io, Error> {
        let mut alpn_protocols = Vec::new();
        if self.http2_enabled {
            alpn_protocols.push(b"h2".to_vec());
        }
        if self.http1_enabled {
            alpn_protocols.push(b"http/1.1".to_vec());
        }
        self.tls_config.alpn_protocols = alpn_protocols;

        if self.uri_scheme == http::uri::Scheme::HTTP && !self.https_only {
            return Ok(Io {
                protocols: Protocols {
                    http1_support: true,
                    http2_support: false,
                },
                uri_host: self.uri_host,
                stream: IoStream {
                    kind: IoKind::Tcp(
                        IoTcp {
                            stream: self.stream,
                        },
                    ),
                },
            });
        }
        if self.uri_scheme != http::uri::Scheme::HTTPS {
            return Err(Error::UriUnsupportedHttpsScheme {
                uri: self.uri,
                scheme: self.uri_scheme,
            });
        }

        let mut hostname =
            match self.override_server_name.as_deref() {
                Some(server_name) =>
                    server_name,
                None =>
                    &self.uri_host,
            };

        hostname = hostname
            .trim_start_matches('[')
            .trim_end_matches(']');

        let server_name = rustls::pki_types::ServerName::try_from(hostname)
            .map_err(|error| Error::TlsInvalidDnsName {
                hostname: hostname.to_string(),
                error,
            })?
            .to_owned();

        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(self.tls_config));
        let tls = connector
            .connect(server_name, self.stream.into_inner())
            .await
            .map_err(Error::ConnectionTls)?;

        Ok(Io {
            protocols: Protocols {
                http1_support: self.http1_enabled,
                http2_support: self.http2_enabled,
            },
            uri_host: self.uri_host,
            stream: IoStream {
                kind: IoKind::TcpTls(
                    IoTcpTls {
                        stream: TokioIo::new(tls),
                    },
                ),
            },
        })
    }
}

async fn connection_establish_tcp(
    mut http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
    uri: Uri,
)
    -> Result<TokioIo<TcpStream>, Error>
{
    tower_service::Service::call(&mut http_connector, uri).await
        .map_err(|error| {
            Error::Connection(Box::new(error) as Box<dyn std::error::Error>)
        })
}

async fn connection_establish_proxy(
    proxy_addr: Uri,
    proxy_auth: Option<Socks5Auth>,
    mut http_connector: legacy::connect::HttpConnector<resolver::HickoryResolver>,
    uri: Uri,
    uri_host: String,
)
    -> Result<TokioIo<TcpStream>, Error>
{
    let port = match uri.port() {
        Some(port) =>
            port.as_u16(),
        None =>
            if uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
                443
            } else {
                80
            },
    };
    let target_addr =
        async_socks5::AddrKind::Domain(uri_host, port);

    let tokio_io_stream =
        tower_service::Service::call(
            &mut http_connector,
            proxy_addr,
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
            proxy_auth.map(Into::into),
        )
        .await
        .map_err(Error::ConnectionViaSocks5)?;

    Ok(TokioIo::new(buf_stream.into_inner()))
}
