use rustls::{
    crypto::{SharedSecret, SupportedKxGroup},
    Error, NamedGroup,
};

use crate::kem::KxGroup;

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
pub const X25519MLKEM768: &dyn SupportedKxGroup = &ReversingKeyExchange {
    inner: KxGroup::new(NamedGroup::X25519MLKEM768, b"x25519_mlkem768\0"),
    classical_len: 32,
};

/// A hack to swap the classical and post quantum parts. See build.rs for more info.
#[derive(Debug, Copy, Clone)]
struct ReversingKeyExchange {
    inner: KxGroup,
    classical_len: usize,
}

struct ReversingKeyExchangeActive {
    inner: Box<dyn rustls::crypto::ActiveKeyExchange>,
    pub_key: Vec<u8>,
    kx_group: ReversingKeyExchange,
}

impl SupportedKxGroup for ReversingKeyExchange {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        let inner = self.inner.start()?;

        // Move the classical part to the end of the public key
        let mut pub_key = inner.pub_key().to_vec();
        let (classical, post_quantum) = pub_key.split_at_mut(self.classical_len);
        pub_key = [post_quantum, classical].concat();

        Ok(Box::new(ReversingKeyExchangeActive {
            inner,
            pub_key,
            kx_group: *self,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.inner.name()
    }
    fn usable_for_version(&self, version: rustls::ProtocolVersion) -> bool {
        self.inner.usable_for_version(version)
    }
    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::CompletedKeyExchange, rustls::Error> {
        // Swap the classical and post quantum parts
        let key_len = peer_pub_key.len();
        let mut peer_pub_key = peer_pub_key.to_vec();
        let (post_quantum, classical) = peer_pub_key.split_at_mut(key_len - self.classical_len);
        let peer_pub_key = [classical, post_quantum].concat();

        let mut completed = self.inner.start_and_complete(&peer_pub_key)?;

        // move the classical part to the end of the public key
        let mut pub_key = completed.pub_key.clone();
        let (classical, post_quantum) = pub_key.split_at_mut(self.classical_len);
        completed.pub_key = [post_quantum, classical].concat();

        // swap the secret halves
        let secret = completed.secret.secret_bytes().to_vec();
        let (classical, post_quantum) = secret.split_at(secret.len() / 2);
        completed.secret = SharedSecret::from([post_quantum, classical].concat());
        Ok(completed)
    }
}

impl rustls::crypto::ActiveKeyExchange for ReversingKeyExchangeActive {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        // move the classical part to the start of the peer public key
        let key_len = peer_pub_key.len();
        let mut peer_pub_key = peer_pub_key.to_vec();
        let (post_quantum, classical) =
            peer_pub_key.split_at_mut(key_len - self.kx_group.classical_len);
        peer_pub_key = [classical, post_quantum].concat();
        self.inner
            .complete(&peer_pub_key)
            // swap the secret halves
            .map(|secret| {
                let secret = secret.secret_bytes().to_vec();
                let (classical, post_quantum) = secret.split_at(secret.len() / 2);
                SharedSecret::from([post_quantum, classical].concat())
            })
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.inner.group()
    }
}
