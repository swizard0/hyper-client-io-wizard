#![forbid(unsafe_code)]

use std::{
    io,
    pin::{
        Pin,
    },
    task::{
        Poll,
        Context,
    },
};

use tokio::{
    net::{
        TcpStream,
    },
};

pub use hyper_util::{
    rt::{
        TokioIo,
        TokioExecutor,
    },
};

pub mod builder;

mod resolver;

pub struct Io {
    pub protocols: Protocols,
    pub uri_host: String,
    pub stream: IoStream,
}

pub struct Protocols {
    http1_support: bool,
    http2_support: bool,
}

impl Io {
    pub fn resolver_setup() -> builder::ResolverBuilder {
        builder::ResolverBuilder::new()
    }
}

impl Protocols {
    pub fn http1_support_announced(&self) -> bool {
        self.http1_support
    }

    pub fn http2_support_announced(&self) -> bool {
        self.http2_support
    }
}

pub struct IoStream {
    kind: IoKind,
}

enum IoKind {
    Tcp(IoTcp),
    TcpTls(IoTcpTls),
}

struct IoTcp {
    stream: TokioIo<TcpStream>,
}

struct IoTcpTls {
    stream: TokioIo<tokio_rustls::client::TlsStream<TcpStream>>,
}

impl hyper::rt::Read for IoStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: hyper::rt::ReadBufCursor<'_>) -> Poll<Result<(), io::Error>> {
        match &mut self.kind {
            IoKind::Tcp(io) =>
                Pin::new(&mut io.stream).poll_read(cx, buf),
            IoKind::TcpTls(io) =>
                Pin::new(&mut io.stream).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for IoStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        match &mut self.kind {
            IoKind::Tcp(io) =>
                Pin::new(&mut io.stream).poll_write(cx, buf),
            IoKind::TcpTls(io) =>
                Pin::new(&mut io.stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match &mut self.kind {
            IoKind::Tcp(io) =>
                Pin::new(&mut io.stream).poll_flush(cx),
            IoKind::TcpTls(io) =>
                Pin::new(&mut io.stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match &mut self.kind {
            IoKind::Tcp(io) =>
                Pin::new(&mut io.stream).poll_shutdown(cx),
            IoKind::TcpTls(io) =>
                Pin::new(&mut io.stream).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.kind {
            IoKind::Tcp(io) =>
                io.stream.is_write_vectored(),
            IoKind::TcpTls(io) =>
                io.stream.is_write_vectored(),
        }
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<Result<usize, io::Error>> {
        match &mut self.kind {
            IoKind::Tcp(io) =>
                Pin::new(&mut io.stream).poll_write_vectored(cx, bufs),
            IoKind::TcpTls(io) =>
                Pin::new(&mut io.stream).poll_write_vectored(cx, bufs),
        }
    }
}
