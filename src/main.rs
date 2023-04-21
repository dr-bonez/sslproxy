use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use color_eyre::eyre::{bail, Error};
use http::uri::Authority;
use http::Uri;
use serde::Deserialize;

mod logger;
mod server;

const CONFIG_PATH: &str = concat!("/etc/", env!("CARGO_CRATE_NAME"), "/config.toml");
const CERTS_PATH: &str = concat!("/var/lib/", env!("CARGO_CRATE_NAME"), "/certs/");

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    testing: bool,
    bind: IpAddr,
    contact: Vec<String>,
    bindings: BTreeMap<String, String>,
}
impl Config {
    fn validate(&self) -> Result<(), Error> {
        for (hostname, binding) in &self.bindings {
            let hostname_parsed = Authority::from_str(hostname)?;
            let binding_parsed = Uri::from_str(binding)?;
            if hostname != hostname_parsed.host() {
                bail!("Invalid hostname: {hostname}");
            }
            if !matches!(
                binding_parsed.scheme_str(),
                Some("ssl") | Some("tls") | Some("tcp")
            ) {
                bail!(
                    "Invalid protocol for binding: {}",
                    binding_parsed.scheme_str().unwrap_or("NONE")
                );
            }
            if binding_parsed.port_u16().is_none() {
                bail!("{binding}: Must specify port");
            }
            if !matches!(
                binding_parsed.path_and_query().map(|pq| pq.as_str()),
                Some("/") | Some("") | None
            ) {
                bail!("{binding}: May not contain path and query");
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    logger::Logger::init();
    if let Err(e) = async {
        let config: Config = toml::from_str(&tokio::fs::read_to_string(CONFIG_PATH).await?)?;
        config.validate()?;
        server::serve(Arc::new(config)).await?.await?;

        Ok::<_, Error>(())
    }
    .await
    {
        eprintln!("{e}");
        eprintln!("{e:?}");
    }
}
