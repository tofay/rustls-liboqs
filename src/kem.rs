//! Key Encapsulation Mechanism (KEM) key exchange groups.
use crate::ffi::{PKeyRefExt, PkeyCtxExt, PkeyCtxRefKemExt, PkeyExt};
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, ProtocolVersion};
use zeroize::Zeroize;

/// This is the [MLKEM] key exchange.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement
pub const MLKEM768: &dyn SupportedKxGroup = &KxGroup::new(NamedGroup::MLKEM768, b"mlkem768\0");

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
pub const X25519MLKEM768: &dyn SupportedKxGroup =
    &KxGroup::new(NamedGroup::X25519MLKEM768, b"X25519MLKEM768\0");

/// A key exchange group based on a key encapsulation mechanism.
#[derive(Debug, Copy, Clone)]
pub struct KxGroup {
    named_group: NamedGroup,
    algorithm_name: &'static [u8],
}

impl KxGroup {
    /// Create a new key exchange group with the specified named group and OpenSSL algorithm name.
    /// The name should be a null terminated string, e.g `b"kyber768\0"`.
    pub const fn new(named_group: NamedGroup, algorithm_name: &'static [u8]) -> Self {
        Self {
            named_group,
            algorithm_name,
        }
    }
}

struct KeyExchange {
    priv_key: PKey<Private>,
    pub_key: Vec<u8>,
    mlkem: KxGroup,
    classical_pub_key: Option<Vec<u8>>,
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        PkeyCtx::<()>::new_from_name(self.algorithm_name)
            .and_then(|mut pkey_ctx| {
                pkey_ctx.keygen_init()?;
                let priv_key = pkey_ctx.keygen()?;

                // Don't use raw_public_key_bytes, as get octet string doesn't add classical length header for hybrid keys
                // https://github.com/open-quantum-safe/oqs-provider/issues/572
                const OSSL_PKEY_PARAM_ENCODED_PUB_KEY: &[u8] = b"encoded-pub-key\0";
                let pub_key = priv_key.get_octet_string_param(OSSL_PKEY_PARAM_ENCODED_PUB_KEY)?;

                let classical_pub_key = if self.named_group == NamedGroup::X25519MLKEM768 {
                    const OQS_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY: &[u8] =
                        b"hybrid_classical_pub\0";
                    Some(priv_key.get_octet_string_param(OQS_HYBRID_PKEY_PARAM_CLASSICAL_PUB_KEY)?)
                } else {
                    None
                };

                Ok(Box::new(KeyExchange {
                    priv_key,
                    pub_key,
                    mlkem: *self,
                    classical_pub_key,
                }) as Box<dyn ActiveKeyExchange>)
            })
            .map_err(|e| Error::General(format!("OpenSSL keygen error: {e}")))
    }

    fn name(&self) -> NamedGroup {
        self.named_group
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::CompletedKeyExchange, Error> {
        PKey::from_encoded_public_key(peer_pub_key, self.algorithm_name)
            .and_then(|key| {
                let mut ctx = PkeyCtx::new(&key)?;
                ctx.encapsulate_init()?;
                let (out, secret) = ctx.encapsulate_to_vec()?;
                Ok(CompletedKeyExchange {
                    group: self.named_group,
                    pub_key: out,
                    secret: SharedSecret::from(secret.as_slice()),
                })
            })
            .map_err(|e| Error::General(format!("OpenSSL encapsulation error: {e}")))
    }
}

impl ActiveKeyExchange for KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        PkeyCtx::new(&self.priv_key)
            .and_then(|ctx| {
                ctx.decapsulate_init()?;
                let secret = ctx.decapsulate_to_vec(peer_pub_key)?;
                Ok(SharedSecret::from(secret.as_slice()))
            })
            .map_err(|e| Error::General(format!("OpenSSL decapsulation error: {e}")))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.mlkem.named_group
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        if self.mlkem.named_group == NamedGroup::X25519MLKEM768 {
            Some((
                NamedGroup::X25519,
                self.classical_pub_key.as_ref().unwrap().as_slice(),
            ))
        } else {
            None
        }
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        if self.mlkem.named_group == NamedGroup::X25519MLKEM768 {
            PKey::public_key_from_raw_bytes(peer_pub_key, Id::X25519)
                .and_then(|peer_pub_key| {
                    // get the private part of the key
                    const OQS_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY: &[u8] =
                        b"hybrid_classical_priv\0";
                    let mut private_bytes = self
                        .priv_key
                        .get_octet_string_param(OQS_HYBRID_PKEY_PARAM_CLASSICAL_PRIV_KEY)?;
                    let priv_key = PKey::private_key_from_raw_bytes(&private_bytes, Id::X25519)?;
                    private_bytes.zeroize();

                    let mut deriver = Deriver::new(&priv_key)?;
                    deriver.set_peer(&peer_pub_key)?;
                    let secret = deriver.derive_to_vec()?;
                    Ok(SharedSecret::from(secret.as_slice()))
                })
                .map_err(|e| Error::General(format!("OpenSSL error: {e}")))
        } else {
            unreachable!("Should only be called if hybrid_component returns Some(_)")
        }
    }
}
