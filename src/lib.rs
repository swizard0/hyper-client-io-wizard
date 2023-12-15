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

pub struct Io {
    kind: IoKind,
}

impl Io {
    pub fn builder(uri: Uri) -> builder::IoBuilder {
        builder::IoBuilder::new(uri)
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
