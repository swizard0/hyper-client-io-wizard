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

pub struct HickoryResolver {
    hickory_resolver: Arc<AsyncResolver<GenericConnector<TokioRuntimeProvider>>>,
}

pub enum ResolverKind {
    System,
    Google,
    GoogleTls,
    GoogleHttps,
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
        })
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
        let name_clone = name.clone();
        let fut = async move {
            let lookup_ip = resolver.lookup_ip(name_clone.as_str()).await?;
            let socket_addr_iter = lookup_ip
                .iter()
                .map(|ip_addr| (ip_addr, 0).into())
                .collect::<Vec<SocketAddr>>()
                .into_iter();
            Ok(HickoryAddrs { socket_addr_iter, })
        };
        Box::pin(fut)
    }
}
