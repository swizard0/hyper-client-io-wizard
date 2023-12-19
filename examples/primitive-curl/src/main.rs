use std::{
    time::{
        Duration,
    },
};

use clap::{
    Parser,
};

use futures_util::{
    StreamExt,
};

use hyper::{
    client::{
        conn,
    },
};

use hyper_client_io_wizard::{
    Io,
    TokioExecutor,
};

#[derive(Clone, Parser, Debug)]
struct CliArgs {
    /// url to retrieve
    #[clap(short, long)]
    url: String,

    /// connect timeout (in milliseconds)
    #[clap(short, long)]
    connect_timeout_ms: Option<u64>,

    /// socks5 proxy url
    #[clap(short, long)]
    socks5_proxy: Option<String>,

    /// dump response headers
    #[clap(long)]
    dump_headers: bool,

    /// force use only http1 requests
    #[clap(long)]
    http1_only: bool,

    /// additional headers for request
    #[clap(long)]
    header: Vec<String>,

    /// post data (if empty GET request is performed)
    #[clap(short, long)]
    post_data: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    ParseUri {
        url: String,
        error: http::uri::InvalidUri,
    },
    ParseSocks5Proxy {
        url: String,
        error: http::uri::InvalidUri,
    },
    InvalidAdditionalHeader {
        additional_header: String,
    },
    IoBuilder(hyper_client_io_wizard::builder::Error),
    HandshakeHttp1(hyper::Error),
    HandshakeHttp2(hyper::Error),
    HttpProtocolsAreNotAnnounced,
    RequestBuild(http::Error),
    RequestSenderReady(hyper::Error),
    Request(hyper::Error),
    ResponseRead(hyper::Error),
    ResponseDecodeUtf8(std::string::FromUtf8Error),
}

impl From<hyper_client_io_wizard::builder::Error> for Error {
    fn from(error: hyper_client_io_wizard::builder::Error) -> Self {
        Self::IoBuilder(error)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    pretty_env_logger::init();
    let cli_args = CliArgs::parse();
    log::debug!("program starts as: {:?}", cli_args);

    let uri: http::uri::Uri = cli_args.url.parse()
        .map_err(|error| Error::ParseUri {
            url: cli_args.url.clone(),
            error,
        })?;
    log::debug!("using uri: {uri:?}");

    let builder = Io::resolver_setup()
        .system()
        .connection_setup(uri.clone())?
        .connect_timeout(
            cli_args.connect_timeout_ms
                .map(Duration::from_millis),
        );
    let tls_builder = if let Some(socks5_proxy) = &cli_args.socks5_proxy {
        let proxy_uri = socks5_proxy.parse()
            .map_err(|error| Error::ParseSocks5Proxy {
                url: socks5_proxy.clone(),
                error,
            })?;
        log::debug!("using socks5 proxy uri: {proxy_uri:?}");
        builder
            .socks5_proxy_setup(proxy_uri)
            .tls_setup()
            .await?
    } else {
        log::debug!("not using socks5 proxy");
        builder
            .tls_setup()
            .await?
    };
    let mut tls_builder = tls_builder
        .native_roots()?;
    if cli_args.http1_only {
        tls_builder = tls_builder
            .enable_http1();
    } else {
        tls_builder = tls_builder
            .enable_all_versions()
    }
    let io = tls_builder
        .establish()
        .await?;

    let mut request_builder = http::Request::builder()
        .uri(uri);
    let mut host_header_found = false;
    for additional_header in &cli_args.header {
        let (header_name, header_value) = additional_header
            .split_once(": ")
            .ok_or(Error::InvalidAdditionalHeader {
                additional_header: additional_header.to_string(),
            })?;
        if header_name == http::header::HOST {
            host_header_found = true;
        }
        request_builder = request_builder
            .header(header_name, header_value);
    }
    if !host_header_found && !io.protocols.http2_support_announced() {
        request_builder = request_builder
            .header(http::header::HOST, io.uri_host);
    }
    let maybe_request = if let Some(post_data) = cli_args.post_data {
        request_builder
            .method(http::method::Method::POST)
            .body(http_body_util::Full::<hyper::body::Bytes>::new(post_data.into()))
    } else {
        request_builder
            .method(http::method::Method::GET)
            .body(http_body_util::Full::<hyper::body::Bytes>::new(Default::default()))
    };
    let request = maybe_request
        .map_err(Error::RequestBuild)?;
    log::debug!("using request: {:?}", request);

    let response = if io.protocols.http2_support_announced() {
        log::debug!("using http2 protocol");
        let (mut request_sender, connection) = conn::http2::Builder::new(TokioExecutor::new())
            .handshake(io.stream)
            .await
            .map_err(Error::HandshakeHttp2)?;
        tokio::spawn(connection);
        request_sender.ready().await
            .map_err(Error::RequestSenderReady)?;
        request_sender.send_request(request).await
            .map_err(Error::Request)?
    } else if io.protocols.http1_support_announced() {
        log::debug!("using http1 protocol");
        let (mut request_sender, connection) = conn::http1::Builder::new()
            .handshake(io.stream)
            .await
            .map_err(Error::HandshakeHttp1)?;
        tokio::spawn(connection);

        request_sender.send_request(request).await
            .map_err(Error::Request)?
    } else {
        return Err(Error::HttpProtocolsAreNotAnnounced);
    };

    log::info!("response status: {:?}", response.status());

    if cli_args.dump_headers {
        println!("Response headers:");
        println!("{:#?}", response.headers());
    }

    let mut body_stream =
        http_body_util::BodyStream::new(
            response.into_body(),
        );
    let mut response_bytes = Vec::new();
    while let Some(maybe_chunk) = body_stream.next().await {
        let chunk = maybe_chunk
            .map_err(Error::ResponseRead)?;
        if let Some(data) = chunk.data_ref() {
            response_bytes.extend_from_slice(data)
        }
    }
    let response_string = String::from_utf8(response_bytes)
        .map_err(Error::ResponseDecodeUtf8)?;

    println!("Response data:");
    println!("{response_string}");

    Ok(())
}
