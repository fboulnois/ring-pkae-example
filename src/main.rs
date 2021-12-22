use ring::{
    aead::{self, BoundKey, OpeningKey, SealingKey, UnboundKey},
    agreement::{self, EphemeralPrivateKey, PublicKey, UnparsedPublicKey},
    digest,
    error::Unspecified,
    hkdf,
    rand::{SecureRandom, SystemRandom},
    test::rand::FixedSliceRandom,
};

// Derived from ec::curve25519::x25519::PRIVATE_KEY_LEN which is private
const X25519_PRIVATE_KEY_LEN: usize = 32;

// Derived from aead::chacha::KEY_LEN which is private
const CHACHA20_POLY1305_KEY_LEN: usize = 32;

// Wrapper around raw random bytes to be used as salt and nonce
#[derive(Clone, Copy)]
struct RandomBytes {
    salt: [u8; digest::SHA256_OUTPUT_LEN],
    nonce: [u8; aead::NONCE_LEN],
}

impl RandomBytes {
    fn new(rng: &dyn SecureRandom) -> Self {
        let mut salt = [0u8; digest::SHA256_OUTPUT_LEN];
        rng.fill(&mut salt).unwrap();

        let mut nonce = [0u8; aead::NONCE_LEN];
        rng.fill(&mut nonce).unwrap();

        Self { salt, nonce }
    }

    fn salt(&self) -> &[u8] {
        self.salt.as_ref()
    }

    fn nonce(&self) -> [u8; aead::NONCE_LEN] {
        self.nonce
    }
}

// Nonce sequence that can only be used once
struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(rngdata: RandomBytes) -> Self {
        Self(Some(aead::Nonce::assume_unique_for_key(rngdata.nonce())))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, Unspecified> {
        self.0.take().ok_or(Unspecified)
    }
}

// Generic wrapper for HKDF to output hash of specific length
#[derive(Debug, PartialEq)]
struct HashBytes<T: core::fmt::Debug + PartialEq>(T);

impl hkdf::KeyType for HashBytes<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<hkdf::Okm<'_, HashBytes<usize>>> for HashBytes<Vec<u8>> {
    fn from(okm: hkdf::Okm<HashBytes<usize>>) -> Self {
        let mut r = vec![0u8; okm.len().0];
        okm.fill(&mut r).unwrap();
        Self(r)
    }
}

// Create a new X25519 public and private key pair
fn new_keypair_internal(
    rng: &dyn SecureRandom,
) -> Result<(EphemeralPrivateKey, UnparsedPublicKey<PublicKey>), Unspecified> {
    let private = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)?;
    let public = private.compute_public_key()?;
    let unparsed = UnparsedPublicKey::new(&agreement::X25519, public);
    Ok((private, unparsed))
}

fn new_keypair_random(
    rng: &dyn SecureRandom,
) -> Result<(EphemeralPrivateKey, UnparsedPublicKey<PublicKey>), Unspecified> {
    new_keypair_internal(rng)
}

// Do not use this in production, use new_keypair_random instead; this function is used to create reproducible key pairs for testing
fn new_keypair_static(
    _rng: &dyn SecureRandom,
) -> Result<(EphemeralPrivateKey, UnparsedPublicKey<PublicKey>), Unspecified> {
    let bytes = [42u8; X25519_PRIVATE_KEY_LEN];
    let rng = FixedSliceRandom { bytes: &bytes };
    new_keypair_internal(&rng)
}

// Use HKDF to derive output keying material
fn derive_hkdf_okm(key: &[u8], rngdata: RandomBytes) -> Vec<u8> {
    let sha = digest::digest(&digest::SHA256, rngdata.salt());
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, sha.as_ref());
    let prk = salt.extract(key);
    let HashBytes(okm) = prk
        .expand(&[b"example"], HashBytes(CHACHA20_POLY1305_KEY_LEN))
        .unwrap()
        .into();
    okm
}

// Create a shared ChaCha20-Poly1305 key that can be used to encrypt and decrypt data
fn new_shared_key(
    sk: EphemeralPrivateKey,
    pk: UnparsedPublicKey<PublicKey>,
    rngdata: RandomBytes,
) -> UnboundKey {
    let key = agreement::agree_ephemeral(sk, &pk, Unspecified, |key| {
        Ok(derive_hkdf_okm(key, rngdata))
    })
    .unwrap();

    aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap()
}

// Operation to encrypt and sign data
fn encrypt(
    sk: EphemeralPrivateKey,
    pk: UnparsedPublicKey<PublicKey>,
    rngdata: RandomBytes,
    message: Vec<u8>,
) -> Vec<u8> {
    let mut ciphertext = message;

    let aad = aead::Aad::from(b"example");
    let seq = OneNonceSequence::new(rngdata);

    let key = new_shared_key(sk, pk, rngdata);

    let mut seal = SealingKey::new(key, seq);
    seal.seal_in_place_append_tag(aad, &mut ciphertext).unwrap();

    ciphertext
}

// Operation to authenticate and decrypt data
fn decrypt(
    sk: EphemeralPrivateKey,
    pk: UnparsedPublicKey<PublicKey>,
    rngdata: RandomBytes,
    ciphertext: Vec<u8>,
) -> Vec<u8> {
    let mut ciphertext = ciphertext;

    let aad = aead::Aad::from(b"example");
    let seq = OneNonceSequence::new(rngdata);

    let key = new_shared_key(sk, pk, rngdata);

    let mut open = OpeningKey::new(key, seq);
    let plaintext = open.open_in_place(aad, &mut ciphertext).unwrap();

    plaintext.to_vec()
}

fn main() {
    let rng = SystemRandom::new();

    // Create keypairs for public key authenticated encryption
    let (sk0, pk0) = new_keypair_static(&rng).unwrap();
    let (sk1, pk1) = new_keypair_random(&rng).unwrap();

    // Message to encrypt and random bytes to use as salt and nonce
    let message = Vec::from("hello world");
    let rngdata = RandomBytes::new(&rng);

    // Encryption with peer private key and own public key
    let ciphertext = encrypt(sk1, pk0, rngdata, message.clone());

    // Decryption with own private key and peer public key
    let plaintext = decrypt(sk0, pk1, rngdata, ciphertext);

    // Check that plaintext is equivalent to original message
    assert!(message == plaintext);
}
