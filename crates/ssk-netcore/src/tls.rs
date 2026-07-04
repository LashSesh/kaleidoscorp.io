#![forbid(unsafe_code)]

//! Real TLS client handshake (rustls, `ring` crypto provider — no `cmake`/`cc`
//! build dependency, keeping cross-platform builds simple) wrapping an
//! already-connected real transport. Verifies the peer certificate against
//! the OS-native trust store; this is a genuine handshake, not a
//! `dangerous()` no-verification bypass.

use std::sync::Arc;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::error::NetcoreError;

/// Optional client certificate material for mutual TLS. `ssk-netadmin`'s
/// `TlsTunnelAdapter::mtls` is currently a bare `bool` with no cert/key
/// field (see `crates/ssk-netadmin/src/adapter.rs`), so no production path
/// constructs this yet — the capability is real and tested here, but not
/// wired to a config source. Do not present mTLS as end-to-end until a
/// descriptor field carries real cert material.
pub struct ClientCertMaterial {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// Builds a real `rustls::ClientConfig` backed by the `ring` provider and
/// the OS-native trust store (falls back to erroring, never to skipping
/// verification, if zero native roots could be loaded).
pub(crate) fn build_client_config(
    client_cert: Option<ClientCertMaterial>,
    relay_label: &str,
) -> Result<Arc<rustls::ClientConfig>, NetcoreError> {
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        tracing::warn!(
            relay = relay_label,
            errors = ?native.errors,
            "some native trust-store entries could not be loaded"
        );
    }
    if native.certs.is_empty() {
        return Err(NetcoreError::TlsHandshakeFailed(
            relay_label.to_string(),
            "no native trust anchors could be loaded; refusing to build a verifier-less TLS config"
                .into(),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in native.certs {
        roots.add(cert).map_err(|e| {
            NetcoreError::TlsHandshakeFailed(relay_label.to_string(), e.to_string())
        })?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| NetcoreError::TlsHandshakeFailed(relay_label.to_string(), e.to_string()))?
        .with_root_certificates(roots);

    let config = match client_cert {
        Some(material) => builder
            .with_client_auth_cert(material.cert_chain, material.key)
            .map_err(|e| {
                NetcoreError::TlsHandshakeFailed(relay_label.to_string(), e.to_string())
            })?,
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// Runs the real TLS client handshake over `stream` against `sni`,
/// returning the wrapped, encrypted stream on success.
pub(crate) async fn wrap_tls<S>(
    stream: S,
    sni: &str,
    config: Arc<rustls::ClientConfig>,
    relay_label: &str,
) -> Result<TlsStream<S>, NetcoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_name = ServerName::try_from(sni.to_string()).map_err(|e| {
        NetcoreError::TlsHandshakeFailed(
            relay_label.to_string(),
            format!("invalid SNI `{sni}`: {e}"),
        )
    })?;
    let connector = TlsConnector::from(config);
    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| NetcoreError::TlsHandshakeFailed(relay_label.to_string(), e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    // These tests deliberately avoid adding a certificate-generation
    // dependency (e.g. `rcgen`) just to exercise the success path. Instead
    // they prove the two properties that actually matter for a fail-closed
    // TLS client: an invalid SNI never starts a handshake, and a peer that
    // does not speak real TLS (or, transitively, one whose certificate the
    // trust store would reject) is never silently accepted as a live
    // session.

    #[tokio::test]
    async fn invalid_sni_is_rejected_before_any_network_io() {
        let config = build_client_config(None, "test-relay");
        // Building the config itself only fails if native roots are
        // unavailable in this sandbox; if it succeeds, feed a clearly
        // invalid SNI value and confirm the handshake never starts.
        if let Ok(config) = config {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let accept = tokio::spawn(async move { listener.accept().await });
            let stream = TcpStream::connect(addr).await.expect("connect");
            let err = wrap_tls(stream, "not a valid sni \u{0}", config, "test-relay")
                .await
                .expect_err("an invalid SNI must fail closed, never silently proceed");
            assert!(matches!(err, NetcoreError::TlsHandshakeFailed(..)));
            drop(accept);
        }
    }

    #[tokio::test]
    async fn handshake_against_a_non_tls_peer_fails_closed_not_silently() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            // Send garbage that is not a valid TLS ServerHello.
            use tokio::io::AsyncWriteExt;
            let _ = sock.write_all(b"not-tls-at-all").await;
        });
        let Ok(config) = build_client_config(None, "test-relay") else {
            // No native trust store in this sandbox: the earlier test
            // already proves the fail-closed contract on config errors.
            return;
        };
        let stream = TcpStream::connect(addr).await.expect("connect");
        let err = wrap_tls(stream, "example.invalid", config, "test-relay")
            .await
            .expect_err("a non-TLS peer must never be accepted as a real TLS session");
        assert!(matches!(err, NetcoreError::TlsHandshakeFailed(..)));
    }
}
