#![forbid(unsafe_code)]

use tokio::{
    net::{
        TcpStream,
    },
};

use hyper_util::{
    rt::{
        TokioIo,
    },
};

pub mod builder;

mod proxy;
mod resolver;

pub struct Io {
    kind: IoKind,
}

impl Io {
    pub fn resolver_setup() -> builder::ResolverBuilder {
        builder::ResolverBuilder::new()
    }
}

enum IoKind {
    Tcp(IoTcp),
    TcpTls(IoTcpTls),
}

struct IoTcp {
    stream: TokioIo<TcpStream>,
}

struct IoTcpTls {
    stream: (),
}
