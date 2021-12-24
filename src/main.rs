use ring::{
    aead::{self, BoundKey, OpeningKey, SealingKey, UnboundKey},
    agreement::{self, EphemeralPrivateKey, PublicKey, UnparsedPublicKey},
    digest::{self, Digest},
    error::Unspecified,
    hkdf,
    rand::{SecureRandom, SystemRandom},
    test::rand::FixedSliceRandom,
};

/// Derived from the private value `ec::curve25519::x25519::PRIVATE_KEY_LEN`
const X25519_PRIVATE_KEY_LEN: usize = 32;

/// Derived from the private value `aead::chacha::KEY_LEN`
const CHACHA20_POLY1305_KEY_LEN: usize = 32;

/// A nonce sequence that can only be used once
struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: [u8; aead::NONCE_LEN]) -> Self {
        Self(Some(aead::Nonce::assume_unique_for_key(nonce)))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, Unspecified> {
        self.0.take().ok_or(Unspecified)
    }
}

/// A generic HKDF wrapper to output hashes of a specific length
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

/// Creates random bytes to use as salt and nonce
///
/// These values should be recreated any time prior to encrypting a message.
fn new_salt_and_nonce(
    rng: &dyn SecureRandom,
) -> ([u8; digest::SHA256_OUTPUT_LEN], [u8; aead::NONCE_LEN]) {
    let mut salt = [0u8; digest::SHA256_OUTPUT_LEN];
    rng.fill(&mut salt).unwrap();

    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill(&mut nonce).unwrap();

    (salt, nonce)
}

/// Creates a new X25519 public and private keypair
fn new_keypair_internal(
    rng: &dyn SecureRandom,
) -> Result<(EphemeralPrivateKey, UnparsedPublicKey<PublicKey>), Unspecified> {
    let private = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)?;
    let public = private.compute_public_key()?;
    let unparsed = UnparsedPublicKey::new(&agreement::X25519, public);
    Ok((private, unparsed))
}

/// Creates a secure X25519 keypair for key agreement
fn new_keypair_random(
    rng: &dyn SecureRandom,
) -> Result<(EphemeralPrivateKey, UnparsedPublicKey<PublicKey>), Unspecified> {
    new_keypair_internal(rng)
}

/// Creates reproducible keypairs for testing
///
/// **Do not use in production**, use [`new_keypair_random`] instead.
fn new_keypair_static(
    _rng: &dyn SecureRandom,
) -> Result<(EphemeralPrivateKey, UnparsedPublicKey<PublicKey>), Unspecified> {
    let bytes = [42u8; X25519_PRIVATE_KEY_LEN];
    let rng = FixedSliceRandom { bytes: &bytes };
    new_keypair_internal(&rng)
}

/// Hashes the salt and public keys together
fn digest_salt_public_keys(
    self_public_key: &UnparsedPublicKey<PublicKey>,
    peer_public_key: &UnparsedPublicKey<PublicKey>,
    salt: [u8; digest::SHA256_OUTPUT_LEN],
) -> Digest {
    let mut data = Vec::new();
    data.extend_from_slice(&salt);
    data.extend_from_slice(self_public_key.bytes().as_ref());
    data.extend_from_slice(peer_public_key.bytes().as_ref());
    digest::digest(&digest::SHA256, data.as_ref())
}

/// Uses HKDF to derive output keying material (OKM)
///
/// The input keying material (IKM) is the raw X25519 shared secret. The HKDF
/// salt is a hash of the concatenation of random bytes along with the public
/// keys themselves. This ensures each party can prove which exact public keys
/// they intended to perform the key exchange with.
fn derive_hkdf_okm(
    key: &[u8],
    self_public_key: &UnparsedPublicKey<PublicKey>,
    peer_public_key: &UnparsedPublicKey<PublicKey>,
    salt: [u8; digest::SHA256_OUTPUT_LEN],
) -> Vec<u8> {
    let sha = digest_salt_public_keys(self_public_key, peer_public_key, salt);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, sha.as_ref());
    let prk = salt.extract(key);
    let HashBytes(okm) = prk
        .expand(&[b"example"], HashBytes(CHACHA20_POLY1305_KEY_LEN))
        .unwrap()
        .into();
    okm
}

/// Creates a shared key to encrypt and decrypt data
///
/// The shared secret is derived from an X25519 key agreement. As recommended in
/// [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748#section-6.1), the
/// shared secret is passed through a key derivation function (KDF) to create a
/// shared key for added security. HKDF is used as a KDF because it is simple
/// and based on the well-understood hash-based message authentication code
/// (HMAC).
///
/// The shared key is formatted to be used for ChaCha20-Poly1305 authenticated
/// encryption.
fn new_shared_key(
    private_key: EphemeralPrivateKey,
    public_key: &UnparsedPublicKey<PublicKey>,
    self_public_key: &UnparsedPublicKey<PublicKey>,
    peer_public_key: &UnparsedPublicKey<PublicKey>,
    salt: [u8; digest::SHA256_OUTPUT_LEN],
) -> UnboundKey {
    let key = agreement::agree_ephemeral(private_key, public_key, Unspecified, |key| {
        Ok(derive_hkdf_okm(key, self_public_key, peer_public_key, salt))
    })
    .unwrap();

    aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap()
}

/// Encrypts and signs data
///
/// The data is encrypted and signed using the peer private key and your own
/// public key.
fn encrypt(
    peer_private_key: EphemeralPrivateKey,
    self_public_key: &UnparsedPublicKey<PublicKey>,
    peer_public_key: &UnparsedPublicKey<PublicKey>,
    nonce: [u8; aead::NONCE_LEN],
    salt: [u8; digest::SHA256_OUTPUT_LEN],
    message: Vec<u8>,
) -> Vec<u8> {
    let mut ciphertext = message;

    let aad = aead::Aad::from(b"example");
    let seq = OneNonceSequence::new(nonce);

    let key = new_shared_key(
        peer_private_key,
        self_public_key,
        self_public_key,
        peer_public_key,
        salt,
    );

    let mut seal = SealingKey::new(key, seq);
    seal.seal_in_place_append_tag(aad, &mut ciphertext).unwrap();

    ciphertext
}

/// Authenticates and decrypts data
///
/// The data is authenticated and decrypted using your own private key and the
/// peer public key.
fn decrypt(
    self_private_key: EphemeralPrivateKey,
    self_public_key: &UnparsedPublicKey<PublicKey>,
    peer_public_key: &UnparsedPublicKey<PublicKey>,
    nonce: [u8; aead::NONCE_LEN],
    salt: [u8; digest::SHA256_OUTPUT_LEN],
    ciphertext: Vec<u8>,
) -> Vec<u8> {
    let mut ciphertext = ciphertext;

    let aad = aead::Aad::from(b"example");
    let seq = OneNonceSequence::new(nonce);

    let key = new_shared_key(
        self_private_key,
        peer_public_key,
        self_public_key,
        peer_public_key,
        salt,
    );

    let mut open = OpeningKey::new(key, seq);
    let plaintext = open.open_in_place(aad, &mut ciphertext).unwrap();

    plaintext.to_vec()
}

fn main() {
    let rng = SystemRandom::new();

    let (salt, nonce) = new_salt_and_nonce(&rng);

    // Create keypairs for public key authenticated encryption
    let (self_private_key, self_public_key) = new_keypair_static(&rng).unwrap();
    let (peer_private_key, peer_public_key) = new_keypair_random(&rng).unwrap();

    let message = Vec::from("hello world");

    let ciphertext = encrypt(
        peer_private_key,
        &self_public_key,
        &peer_public_key,
        nonce,
        salt,
        message.clone(),
    );

    let plaintext = decrypt(
        self_private_key,
        &self_public_key,
        &peer_public_key,
        nonce,
        salt,
        ciphertext,
    );

    match plaintext == message {
        true => println!("Ok"),
        false => eprintln!("ERROR: Plaintext does not match original message."),
    }
}
