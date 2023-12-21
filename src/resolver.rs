use std::{
    net::{
        SocketAddr,
    },
    sync::{
        Arc,
    },
};

use futures::{
    Future,
};

use hickory_resolver::{
    config::{
        ResolverOpts,
        ResolverConfig,
    },
    name_server::{
        GenericConnector,
        TokioRuntimeProvider,
    },
    error::{
        ResolveError,
    },
    AsyncResolver,
};

use hyper_util::{
    client::{
        legacy::{
            connect::{
                dns,
            },
        },
    },
};

#[derive(Clone)]
pub struct HickoryResolver {
    hickory_resolver: Arc<AsyncResolver<GenericConnector<TokioRuntimeProvider>>>,
    force_ip_kind: Option<ForceIpKind>,
}

pub enum ResolverKind {
    System,
    Google,
    GoogleTls,
    GoogleHttps,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ForceIpKind {
    Ip4,
    Ip6,
}

impl HickoryResolver {
    pub fn new(resolver_kind: ResolverKind) -> Result<Self, ResolveError> {
        let hickory_resolver = match resolver_kind {
            ResolverKind::System =>
                AsyncResolver::tokio_from_system_conf()?,
            ResolverKind::Google =>
                AsyncResolver::tokio(
                    ResolverConfig::google(),
                    ResolverOpts::default(),
                ),
            ResolverKind::GoogleTls =>
                AsyncResolver::tokio(
                    ResolverConfig::google_tls(),
                    ResolverOpts::default(),
                ),
            ResolverKind::GoogleHttps =>
                AsyncResolver::tokio(
                    ResolverConfig::google_https(),
                    ResolverOpts::default(),
                ),
        };


        Ok(Self {
            hickory_resolver: Arc::new(hickory_resolver),
            force_ip_kind: None,
        })
    }

    pub(super) fn force_ip4(&mut self) {
        self.force_ip_kind = Some(ForceIpKind::Ip4);
    }

    pub(super) fn force_ip6(&mut self) {
        self.force_ip_kind = Some(ForceIpKind::Ip6);
    }

    pub(super) fn force_none(&mut self) {
        self.force_ip_kind = None;
    }
}

pub struct HickoryAddrs {
    socket_addr_iter: std::vec::IntoIter<SocketAddr>,
}

impl Iterator for HickoryAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.socket_addr_iter.next()
    }
}

impl tower_service::Service<dns::Name> for HickoryResolver {
    type Response = HickoryAddrs;
    type Error = ResolveError;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: dns::Name) -> Self::Future {
        log::debug!("resolving host: {:?}", name);
        let resolver = self.hickory_resolver.clone();
        let force_ip_kind = self.force_ip_kind;
        let name_clone = name.clone();
        let fut = async move {
            let socket_addrs: Vec<SocketAddr> =
                match force_ip_kind {
                    None => {
                        let lookup_ip = resolver.lookup_ip(name_clone.as_str()).await?;
                        lookup_ip
                            .iter()
                            .map(|ip_addr| (ip_addr, 0).into())
                            .collect()
                    },
                    Some(ForceIpKind::Ip4) => {
                        let lookup_ip4 = resolver.ipv4_lookup(name_clone.as_str()).await?;
                        lookup_ip4
                            .iter()
                            .map(|ip_addr| {
                                let ip: std::net::Ipv4Addr = (*ip_addr).into();
                                (ip, 0).into()
                            })
                            .collect()
                    },
                    Some(ForceIpKind::Ip6) => {
                        let lookup_ip6 = resolver.ipv6_lookup(name_clone.as_str()).await?;
                        lookup_ip6
                            .iter()
                            .map(|ip_addr| {
                                let ip: std::net::Ipv6Addr = (*ip_addr).into();
                                (ip, 0).into()
                            })
                            .collect()
                    },
                };

            Ok(HickoryAddrs {
                socket_addr_iter: socket_addrs.into_iter(),
            })
        };
        Box::pin(fut)
    }
}
