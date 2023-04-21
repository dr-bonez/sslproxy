use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

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
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
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
                Ok((mut stream, _)) => {
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
                                    let mut tcp =
                                        TcpStream::connect((resolved, binding.port_u16().unwrap()))
                                            .await?;
                                    match binding.scheme().unwrap().as_str() {
                                        "tcp" => {
                                            tokio::io::copy_bidirectional(&mut stream, &mut tcp)
                                                .await?;
                                        }
                                        "ssl" | "tls" => {
                                            tokio::io::copy_bidirectional(
                                                &mut stream,
                                                &mut TlsConnector::from(client_config)
                                                    .connect(host.try_into()?, tcp)
                                                    .await?,
                                            )
                                            .await?;
                                        }
                                        _ => unreachable!("config is prevalidated"),
                                    }
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
