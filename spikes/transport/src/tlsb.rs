//! Вариант B: TLS-конфиги rustls для quinn. Голые публичные ключи (RFC 7250), только TLS 1.3,
//! одноразовый ключ сервера на каждое входящее, клиент без пиннинга с проверкой подписи рукопожатия.
//! Своей криптографии нет: ключи и подписи делают ed25519-dalek и ring через rustls.
use std::fmt;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::{AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage};
use rustls::sign::{CertifiedKey, public_key_to_spki};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::keys::rand32;
use crate::util::{BoxErr, err};

pub const ALPN: &[u8] = b"chervo-spike/1";
/// Имя сервера в B: при `enable_sni = false` в сеть не уходит.
pub const SERVER_NAME: &str = "chervo.invalid";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Одноразовый серверный конфиг и SPKI, который он предъявляет.
pub struct Issued {
    pub cfg: Arc<rustls::ServerConfig>,
    pub spki: Vec<u8>,
}

/// Новый ключ Ed25519 на каждый вызов. `mismatch`: SPKI от ключа K2, подпись ключом K1 (проверка G9(3)).
pub fn ephemeral_server(mismatch: bool) -> Result<Issued, BoxErr> {
    let sk = SigningKey::from_bytes(&rand32()?);
    let der = sk.to_pkcs8_der().map_err(|e| err(format!("pkcs8: {e}")))?;
    let key = rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(der.as_bytes()))
        .map_err(|e| err(format!("ring не принял PKCS#8 от dalek: {e}")))?;
    let advertised = if mismatch {
        SigningKey::from_bytes(&rand32()?).verifying_key().to_bytes()
    } else {
        sk.verifying_key().to_bytes()
    };
    let spki: SubjectPublicKeyInfoDer<'static> = public_key_to_spki(&rustls::pki_types::alg_id::ED25519, advertised);
    let spki_bytes = spki.as_ref().to_vec();
    let ck = CertifiedKey::new(vec![CertificateDer::from(spki_bytes.clone())], key);
    let mut sc = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| err(format!("tls13: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(ck))));
    sc.alpn_protocols = vec![ALPN.to_vec()];
    sc.max_early_data_size = 0;
    sc.send_tls13_tickets = 0;
    sc.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Issued { cfg: Arc::new(sc), spki: spki_bytes })
}

/// Клиентский верификатор: ключ сервера не пиннится (он одноразовый), но подпись рукопожатия
/// проверяется открытым ключом из присланного SPKI.
struct RpkVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for RpkVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RpkVerifier")
    }
}

impl ServerCertVerifier for RpkVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(cert.as_ref()), dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

pub fn client_tls() -> Result<Arc<rustls::ClientConfig>, BoxErr> {
    let p = provider();
    let algs = p.signature_verification_algorithms;
    let mut cc = rustls::ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| err(format!("tls13: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RpkVerifier { algs }))
        .with_no_client_auth();
    cc.alpn_protocols = vec![ALPN.to_vec()];
    cc.enable_sni = false;
    cc.enable_early_data = false;
    cc.resumption = Resumption::disabled();
    Ok(Arc::new(cc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_accepts_dalek_pkcs8_and_keys_differ() {
        let a = ephemeral_server(false).map(|i| i.spki);
        let b = ephemeral_server(false).map(|i| i.spki);
        assert!(a.is_ok() && b.is_ok());
        assert_ne!(a.ok(), b.ok());
    }

    #[test]
    fn client_tls_builds() {
        assert!(client_tls().is_ok());
    }
}
