# hyper-client-io-wizard
[Documentation](https://docs.rs/hyper-client-io-wizard) | [Crates.io](https://crates.io/crates/hyper-client-io-wizard) | [Repository](https://github.com/swizard0/hyper-client-io-wizard)

## Why hyper-client-io-wizard?
This project's goal is to provide a simple and straightforward connection builder for [hyper v1](https://crates.io/crates/hyper) HTTP client.

## Features
Currently supports following configurations:

* Direct connections (similar to [hyper_util::client::legacy](https://docs.rs/hyper-util/latest/hyper_util/client/legacy/index.html))
* Socks5 proxy (based on [async-socks5](https://crates.io/crates/async-socks5) crate)
* TLS connections (based on [tokio-rustls](https://crates.io/crates/tokio-rustls) crate)
* Customizable DNS resolving (based on [hickory-resolver](https://crates.io/crates/hickory-resolver) crate)

## Usage
See the `examples` folder in the repository for more examples, i.e. `primitive-curl` command line utility.

```rust
    let io = Io::resolver_setup()
        .system()
        .connection_setup(target_uri)?
        .connect_timeout(Some(Duration::from_millis(1000)))
        .socks5_proxy_setup(proxy_uri)
        .tls_setup()
        .await?
        .native_roots()?
        .enable_all_versions()
        .establish()
        .await?;

    let (mut request_sender, connection) = conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io.stream)
        .await?;
    tokio::spawn(connection);
    let response = request_sender.send_request(request).await?;

    ...
```

## License
This project is licensed under `MIT`.
