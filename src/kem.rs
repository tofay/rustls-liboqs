//! Key Encapsulation Mechanism (KEM) key exchange groups.
use crate::ffi::{PKeyRefExt, PkeyCtxExt, PkeyCtxRefKemExt, PkeyExt};
use openssl::pkey::{PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, ProtocolVersion};

/// This is the [MLKEM] key exchange.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement
pub const MLKEM768: &dyn SupportedKxGroup = &KxGroup::new(NamedGroup::MLKEM768, b"mlkem768\0");

#[cfg(not(swapx25519hybrid))]
/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
pub const X25519MLKEM768: &dyn SupportedKxGroup =
    &KxGroup::new(NamedGroup::X25519MLKEM768, b"x25519_mlkem768\0");

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
}

const OSSL_PKEY_PARAM_ENCODED_PUB_KEY: &[u8] = b"encoded-pub-key\0";

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        PkeyCtx::<()>::new_from_name(self.algorithm_name)
            .and_then(|mut pkey_ctx| {
                pkey_ctx.keygen_init()?;
                let priv_key = pkey_ctx.keygen()?;
                // Get octet string doesn't add classical length header for hybrid keys
                // https://github.com/open-quantum-safe/oqs-provider/issues/572
                let pub_key = priv_key.get_octet_string_param(OSSL_PKEY_PARAM_ENCODED_PUB_KEY)?;
                Ok(Box::new(KeyExchange {
                    priv_key,
                    pub_key,
                    mlkem: *self,
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
}
