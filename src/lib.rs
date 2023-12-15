use http::{
    uri::{
        Uri,
    },
};

use tokio::{
    net::{
        TcpStream,
    },
};

pub mod builder;
pub mod resolver;

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
    TcpSocks(IoTcpSocks),
    TcpTls(IoTcpTls),
    TcpSocksTls(IoTcpSocksTls),
}

struct IoTcp {
    stream: TcpStream,
}

struct IoTcpSocks {
    stream: (),
}

struct IoTcpTls {
    stream: (),
}

struct IoTcpSocksTls {
    stream: (),
}
