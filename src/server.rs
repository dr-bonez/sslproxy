use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use async_acme::acme::ACME_TLS_ALPN_NAME;
use color_eyre::eyre::eyre;
use color_eyre::eyre::Error;
use http::Uri;
use rustls::server::Acceptor;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::Certificate;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Sleep;
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::StreamExt;
use trust_dns_resolver::TokioAsyncResolver;

use crate::{Config, CERTS_PATH};

struct SingleCertResolver(Arc<CertifiedKey>);
impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[pin_project::pin_project]
pub struct TimeoutStream<S: AsyncRead + AsyncWrite = TcpStream> {
    timeout: Duration,
    #[pin]
    sleep: Sleep,
    #[pin]
    stream: S,
}
impl<S: AsyncRead + AsyncWrite> TimeoutStream<S> {
    pub fn new(stream: S, timeout: Duration) -> Self {
        Self {
            timeout,
            sleep: tokio::time::sleep(timeout),
            stream,
        }
    }
}
impl<S: AsyncRead + AsyncWrite> AsyncRead for TimeoutStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut this = self.project();
        if let std::task::Poll::Ready(_) = this.sleep.as_mut().poll(cx) {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out",
            )));
        }
        let res = this.stream.poll_read(cx, buf);
        if res.is_ready() {
            this.sleep.reset(Instant::now() + *this.timeout);
        }
        res
    }
}
impl<S: AsyncRead + AsyncWrite> AsyncWrite for TimeoutStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let mut this = self.project();
        if let std::task::Poll::Ready(_) = this.sleep.as_mut().poll(cx) {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out",
            )));
        }
        let res = this.stream.poll_write(cx, buf);
        if res.is_ready() {
            this.sleep.reset(Instant::now() + *this.timeout);
        }
        res
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let mut this = self.project();
        if let std::task::Poll::Ready(_) = this.sleep.as_mut().poll(cx) {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out",
            )));
        }
        let res = this.stream.poll_flush(cx);
        if res.is_ready() {
            this.sleep.reset(Instant::now() + *this.timeout);
        }
        res
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let mut this = self.project();
        if let std::task::Poll::Ready(_) = this.sleep.as_mut().poll(cx) {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out",
            )));
        }
        let res = this.stream.poll_shutdown(cx);
        if res.is_ready() {
            this.sleep.reset(Instant::now() + *this.timeout);
        }
        res
    }
}

pub(crate) async fn serve(config: Arc<Config>) -> Result<JoinHandle<()>, Error> {
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(
                tokio::task::spawn_blocking(|| rustls_native_certs::load_native_certs())
                    .await??
                    .into_iter()
                    .fold(Ok::<_, Error>(RootCertStore::empty()), |acc, x| {
                        let mut acc = acc?;
                        acc.add(&Certificate(x.0))?;
                        Ok(acc)
                    })?,
            )
            .with_no_client_auth(),
    );
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let acme_tls_alpn_cache = Arc::new(Mutex::new(BTreeMap::<
        String,
        watch::Receiver<Option<Arc<CertifiedKey>>>,
    >::new()));
    let listener = TcpListener::bind(config.bind).await?;
    let server = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let mut stream = Box::pin(TimeoutStream::new(stream, Duration::from_secs(300)));
                    let config = config.clone();
                    let acme_tls_alpn_cache = acme_tls_alpn_cache.clone();
                    let resolver = resolver.clone();
                    let client_config = client_config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = async {
                            let mid =
                                LazyConfigAcceptor::new(Acceptor::default(), &mut stream).await?;
                            let domain = mid.client_hello().server_name().map(|s| s.to_owned());
                            let binding = if let Some(domain) = &domain {
                                config
                                    .bindings
                                    .get(domain)
                                    .map(|b| Uri::from_str(b))
                                    .transpose()?
                            } else {
                                None
                            };
                            if let (Some(domain), Some(binding)) = (&domain, binding) {
                                if mid
                                    .client_hello()
                                    .alpn()
                                    .into_iter()
                                    .flatten()
                                    .any(|alpn| alpn == ACME_TLS_ALPN_NAME)
                                {
                                    let cert = WatchStream::new(
                                        acme_tls_alpn_cache
                                            .lock()
                                            .await
                                            .get(domain)
                                            .cloned()
                                            .ok_or_else(|| {
                                                eyre!("No challenge recv available for {domain}")
                                            })?,
                                    );
                                    tracing::info!("Waiting for verification cert");
                                    let cert = cert
                                        .filter(|c| c.is_some())
                                        .next()
                                        .await
                                        .flatten()
                                        .ok_or_else(|| {
                                            eyre!("No challenge available for {domain}")
                                        })?;
                                    tracing::info!("Verification cert received");
                                    let mut cfg = ServerConfig::builder()
                                        .with_safe_defaults()
                                        .with_no_client_auth()
                                        .with_cert_resolver(Arc::new(SingleCertResolver(cert)));

                                    cfg.alpn_protocols = vec![ACME_TLS_ALPN_NAME.to_vec()];
                                    mid.into_stream(Arc::new(cfg)).await?;
                                } else {
                                    let domains = [domain.to_string()];
                                    let (send, recv) = watch::channel(None);
                                    acme_tls_alpn_cache
                                        .lock()
                                        .await
                                        .insert(domain.clone(), recv);
                                    let cert = async_acme::rustls_helper::order(
                                        |_, cert| {
                                            send.send_replace(Some(Arc::new(cert)));
                                            Ok(())
                                        },
                                        if config.testing {
                                            async_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY
                                        } else {
                                            async_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY
                                        },
                                        &domains,
                                        Some(&CERTS_PATH),
                                        &config.contact,
                                    )
                                    .await?;
                                    tracing::info!("Cert found");
                                    let cfg = ServerConfig::builder()
                                        .with_safe_defaults()
                                        .with_no_client_auth()
                                        .with_cert_resolver(Arc::new(SingleCertResolver(
                                            Arc::new(cert),
                                        )));
                                    let mut stream = mid.into_stream(Arc::new(cfg)).await?;
                                    let host = binding.host().unwrap();
                                    let resolved = if let Ok(ip) = host.parse::<IpAddr>() {
                                        ip
                                    } else {
                                        resolver
                                            .lookup_ip(format!("{}.", host))
                                            .await?
                                            .iter()
                                            .next()
                                            .ok_or_else(|| eyre!("NXDOMAIN for {binding}"))?
                                    };
                                    let tcp =
                                        TcpStream::connect((resolved, binding.port_u16().unwrap()))
                                            .await?;
                                    let mut tcp =
                                        Box::pin(TimeoutStream::new(tcp, Duration::from_secs(300)));
                                    let tcp_res = match binding.scheme().unwrap().as_str() {
                                        "tcp" => {
                                            tokio::io::copy_bidirectional(&mut stream, &mut tcp)
                                                .await
                                        }
                                        "ssl" | "tls" => {
                                            tokio::io::copy_bidirectional(
                                                &mut stream,
                                                &mut TlsConnector::from(client_config)
                                                    .connect(host.try_into()?, tcp)
                                                    .await?,
                                            )
                                            .await
                                        }
                                        _ => unreachable!("config is prevalidated"),
                                    };
                                    match tcp_res {
                                        Ok(_) => Ok(()),
                                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                            Ok(())
                                        }
                                        Err(e) => Err(e),
                                    }?;
                                }

                                Ok::<_, Error>(())
                            } else {
                                Err(eyre!("Unknown domain: {domain:?}"))
                            }
                        }
                        .await
                        {
                            tracing::error!("SSL Error: {e}");
                            tracing::debug!("{e:?}");
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("TCP Error: {e}");
                    tracing::debug!("{e:?}");
                }
            }
        }
    });

    Ok(server)
}
