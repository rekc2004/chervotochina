//! TLS 1.3 с голыми публичными ключами (RFC 7250): одноразовый ключ сервера на каждое
//! входящее соединение, закрытый базовый конфиг гнезда, клиент без пиннинга.
//! Своей криптографии нет: ключи и подписи делают ring и rustls.

use std::fmt;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{IdleTimeout, NoneTokenLog, ValidationTokenConfig, VarInt};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key,
};
use rustls::pki_types::{
    CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::{
    AlwaysResolvesServerRawPublicKeys, ClientHello, NoServerSessionStorage, ResolvesServerCert,
};
use rustls::sign::{CertifiedKey, public_key_to_spki};
use rustls::{DigitallySignedStruct, SignatureScheme};
use zeroize::Zeroizing;

use crate::{ALPN, QuinnConfig};

/// Любая ошибка сборки конфигурации: наружу причина не отдаётся.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TlsError;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Роль для параметров транспорта до аутентификации.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Server,
    Client,
}

/// Транспортные параметры до конца KK: сервер принимает один двунаправленный поток,
/// клиент не принимает потоков; однонаправленных и датаграмм нет; окно соединения мало.
pub(crate) fn pre_auth_transport(cfg: &QuinnConfig, role: Role) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    let bidi = match role {
        Role::Server => 1,
        Role::Client => 0,
    };
    t.max_concurrent_bidi_streams(VarInt::from_u32(bidi));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.datagram_receive_buffer_size(None);
    t.receive_window(VarInt::from_u32(cfg.preauth_receive_window));
    t.max_idle_timeout(IdleTimeout::try_from(cfg.idle_timeout).ok());
    t.keep_alive_interval(Some(cfg.keep_alive));
    Arc::new(t)
}

/// Резолвер базового конфига гнезда: всегда отказ. Случайный `Incoming::accept()` даёт
/// провал рукопожатия, а не постоянный ключ.
struct ClosedResolver;

impl fmt::Debug for ClosedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClosedResolver")
    }
}

impl ResolvesServerCert for ClosedResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

fn harden(sc: &mut rustls::ServerConfig) {
    sc.alpn_protocols = vec![ALPN.to_vec()];
    sc.max_early_data_size = 0;
    sc.send_tls13_tickets = 0;
    sc.session_storage = Arc::new(NoServerSessionStorage {});
}

fn quic_server(
    sc: rustls::ServerConfig,
    cfg: &QuinnConfig,
) -> Result<quinn::ServerConfig, TlsError> {
    let quic = QuicServerConfig::try_from(Arc::new(sc)).map_err(|_| TlsError)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server.transport_config(pre_auth_transport(cfg, Role::Server));
    let mut tokens = ValidationTokenConfig::default();
    tokens.sent(0).log(Arc::new(NoneTokenLog));
    server.validation_token_config(tokens);
    Ok(server)
}

/// Базовый конфиг гнезда: закрыт (резолвер всегда `None`), плюс лимиты `Endpoint`.
pub(crate) fn base_server_config(cfg: &QuinnConfig) -> Result<quinn::ServerConfig, TlsError> {
    let mut sc = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsError)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ClosedResolver));
    harden(&mut sc);
    let mut server = quic_server(sc, cfg)?;
    server
        .max_incoming(cfg.max_incoming)
        .incoming_buffer_size(cfg.incoming_buffer)
        .incoming_buffer_size_total(cfg.incoming_buffer_total);
    Ok(server)
}

/// Новый одноразовый конфиг сервера с новым ключом Ed25519 (ring).
pub(crate) fn ephemeral_server_config(
    cfg: &QuinnConfig,
) -> Result<Arc<quinn::ServerConfig>, TlsError> {
    let rng = SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| TlsError)?;
    let der = Zeroizing::new(doc.as_ref().to_vec());
    let pair = Ed25519KeyPair::from_pkcs8(&der).map_err(|_| TlsError)?;
    let spki: SubjectPublicKeyInfoDer<'static> = public_key_to_spki(
        &rustls::pki_types::alg_id::ED25519,
        pair.public_key().as_ref(),
    );
    let key = rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(der.as_slice()))
        .map_err(|_| TlsError)?;
    let ck = CertifiedKey::new(vec![CertificateDer::from(spki.as_ref().to_vec())], key);
    let mut sc = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsError)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            ck,
        ))));
    harden(&mut sc);
    Ok(Arc::new(quic_server(sc, cfg)?))
}

/// Клиентский верификатор: ключ сервера одноразовый и не пиннится, подпись рукопожатия
/// проверяется ключом из присланного SPKI; только Ed25519.
pub(crate) struct RpkVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl RpkVerifier {
    pub(crate) fn new() -> Self {
        Self {
            algs: provider().signature_verification_algorithms,
        }
    }
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
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// TLS клиента: только TLS 1.3, без SNI, без возобновления и 0-RTT.
pub(crate) fn client_rustls() -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let mut cc = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsError)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RpkVerifier::new()))
        .with_no_client_auth();
    cc.alpn_protocols = vec![ALPN.to_vec()];
    cc.enable_sni = false;
    cc.enable_early_data = false;
    cc.resumption = Resumption::disabled();
    Ok(Arc::new(cc))
}

pub(crate) fn client_quic() -> Result<Arc<QuicClientConfig>, TlsError> {
    let quic = QuicClientConfig::try_from(client_rustls()?).map_err(|_| TlsError)?;
    Ok(Arc::new(quic))
}

/// Готовый `quinn::ClientConfig` для звонка: без хранилища токенов, параметры до KK.
pub(crate) fn client_config(
    quic: &Arc<QuicClientConfig>,
    transport: &Arc<quinn::TransportConfig>,
) -> quinn::ClientConfig {
    let mut cc = quinn::ClientConfig::new(quic.clone());
    cc.token_store(Arc::new(quinn::NoneTokenStore));
    cc.transport_config(transport.clone());
    cc
}
