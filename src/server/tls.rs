use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

use crate::config::VhostConfig;
use rustls::{
    pki_types::PrivateKeyDer, server::ClientHello, sign::CertifiedKey, ServerConfig,
    ServerConnection, StreamOwned,
};

#[derive(Clone, Debug)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

impl TlsAcceptor {
    pub fn from_pem_with_vhosts(
        cert: &Path,
        key: &Path,
        vhosts: &[VhostConfig],
    ) -> io::Result<Self> {
        let default = load_certified_key(cert, key)?;
        let mut named = HashMap::new();
        for vhost in vhosts {
            match (&vhost.tls_certificate, &vhost.tls_private_key) {
                (Some(cert), Some(key)) => {
                    named.insert(vhost.host.clone(), load_certified_key(cert, key)?);
                }
                (None, None) => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "vhost {} must specify both TLS certificate and private key",
                            vhost.host
                        ),
                    ))
                }
            }
        }
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniResolver { default, named }));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
        })
    }
    pub fn accept(&self, stream: TcpStream) -> io::Result<TlsStream> {
        let connection = ServerConnection::new(Arc::clone(&self.config)).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("TLS setup failed: {e}"))
        })?;
        let mut tls = StreamOwned::new(connection, stream);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock)?;
        }
        Ok(tls)
    }
}

#[derive(Debug)]
struct SniResolver {
    default: Arc<CertifiedKey>,
    named: HashMap<String, Arc<CertifiedKey>>,
}
impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        hello
            .server_name()
            .and_then(|name| self.named.get(name).cloned())
            .or_else(|| Some(self.default.clone()))
    }
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> io::Result<Arc<CertifiedKey>> {
    let cert_file = File::open(cert_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot open TLS certificate {}: {e}", cert_path.display()),
        )
    })?;
    let key_file = File::open(key_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot open TLS private key {}: {e}", key_path.display()),
        )
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TLS certificate: {e}"),
            )
        })?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS certificate PEM contains no certificates",
        ));
    }
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TLS private key: {e}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS private key PEM contains no private key",
            )
        })?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported TLS private key: {e}"),
        )
    })?;
    let certified = CertifiedKey::new(certificates, signing_key);
    certified.keys_match().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("certificate/private key mismatch: {e}"),
        )
    })?;
    Ok(Arc::new(certified))
}

pub type TlsStream = StreamOwned<ServerConnection, TcpStream>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_certificate_is_rejected_without_panic() {
        let err = TlsAcceptor::from_pem_with_vhosts(
            Path::new("/no/such/cert.pem"),
            Path::new("/no/such/key.pem"),
            &[],
        )
        .expect_err("missing certificate must fail");
        assert!(err.to_string().contains("TLS certificate"));
    }
}
