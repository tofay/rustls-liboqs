//! Experimental post-quantum key exchange algorithms for rustls using OpenSSL and liboqs.
#![deny(missing_docs)]
mod ffi;
mod kem;
#[cfg(swapx25519hybrid)]
mod swap;

pub use kem::MLKEM768;
#[cfg(not(swapx25519hybrid))]
pub use kem::X25519MLKEM768;
#[cfg(swapx25519hybrid)]
pub use swap::X25519MLKEM768;

#[cfg(test)]
mod tests {
    use once_cell::sync::OnceCell;
    use openssl::provider::Provider;
    use rustls::crypto::SupportedKxGroup;

    use crate::{MLKEM768, X25519MLKEM768};

    fn load_providers() {
        static INSTANCE: OnceCell<Vec<Provider>> = OnceCell::new();
        INSTANCE.get_or_init(|| {
            let default_provider = openssl::provider::Provider::load(None, "default").unwrap();
            let oqs_provider = openssl::provider::Provider::load(None, "oqsprovider").unwrap();
            let _ = openssl::error::ErrorStack::get();
            vec![default_provider, oqs_provider]
        });
    }

    pub(crate) fn roundtrip(ours: &dyn SupportedKxGroup, theirs: &dyn SupportedKxGroup) {
        load_providers();

        let our_kx = ours.start().unwrap();
        let their_kx = theirs.start().unwrap();

        let our_completed = ours.start_and_complete(their_kx.pub_key()).unwrap();
        let their_secret = their_kx.complete(&our_completed.pub_key).unwrap();

        assert_eq!(
            our_completed.secret.secret_bytes(),
            their_secret.secret_bytes()
        );

        let their_completed = theirs.start_and_complete(our_kx.pub_key()).unwrap();
        let our_secret = our_kx.complete(&their_completed.pub_key).unwrap();

        assert_eq!(
            our_secret.secret_bytes(),
            their_completed.secret.secret_bytes()
        );
    }

    #[test]
    fn mlkem768() {
        roundtrip(MLKEM768, rustls_post_quantum::MLKEM768);
    }

    #[test]
    fn x25519_mlkem768() {
        roundtrip(X25519MLKEM768, rustls_post_quantum::X25519MLKEM768);
    }
}
