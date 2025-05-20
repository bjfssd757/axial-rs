#![cfg(feature = "crypto")]

use std::num::NonZeroU32;
use base64::engine::general_purpose;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, AES_128_GCM, NONCE_LEN};
use ring::digest::{digest, SHA256, SHA384, SHA512};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use ring::rand::{SystemRandom, SecureRandom};
use base64::Engine;

#[derive(Clone, Debug)]
pub enum CryptoError {
    InvalidKeyLength,
    EncryptionError,
    DecryptionError,
    PBKDF2Error, 
    VerificationFailed,
    
    PqCryptoError(String),
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidSignature,
    InvalidCiphertext,
    KEMError,

    InvalidNonce,
    InvalidKey,
    InvalidInput(String),
    InvalidTag,
    InvalidLength(String),
    InvalidFormat(String),

    RingUnspecified,
    RingRandomUnspecified,
    Utf8Error(std::string::FromUtf8Error),
    Base64Error(base64::DecodeError),
    InternalError(String),
}


impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length: must be 16 or 32 bytes for AES-128-GCM or AES-256-GCM respectively"),
            CryptoError::EncryptionError => write!(f, "Encryption failed"),
            CryptoError::DecryptionError => write!(f, "Decryption failed (authentication tag mismatch or invalid ciphertext)"),
            CryptoError::PBKDF2Error => write!(f, "PBKDF2 operation failed"),
            CryptoError::VerificationFailed => write!(f, "Verification failed (e.g., password mismatch, signature invalid)"),
            CryptoError::PqCryptoError(s) => write!(f, "Post-quantum crypto error: {}", s),
            CryptoError::InvalidPublicKey => write!(f, "Invalid public key format or content"),
            CryptoError::InvalidPrivateKey => write!(f, "Invalid private key format or content"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature format or verification failed"),
            CryptoError::InvalidCiphertext => write!(f, "Invalid ciphertext format or content"),
            CryptoError::KEMError => write!(f, "Key Encapsulation Mechanism failed"),
            CryptoError::InvalidNonce => write!(f, "Invalid nonce: incorrect length or format"),
            CryptoError::InvalidKey => write!(f, "Invalid key material or format"),
            CryptoError::InvalidInput(s) => write!(f, "Invalid input: {}", s),
            CryptoError::InvalidTag => write!(f, "Invalid authentication tag for AEAD cipher"),
            CryptoError::InvalidLength(s) => write!(f, "Invalid length: {}", s),
            CryptoError::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
            CryptoError::RingUnspecified => write!(f, "Underlying crypto library error (ring unspecified)"),
            CryptoError::RingRandomUnspecified => write!(f, "Underlying crypto library random number generation error (ring unspecified)"),
            CryptoError::Utf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
            CryptoError::Base64Error(e) => write!(f, "Base64 decoding error: {}", e),
            CryptoError::InternalError(s) => write!(f, "Internal error: {}", s),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::Utf8Error(e) => Some(e),
            CryptoError::Base64Error(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ring::error::Unspecified> for CryptoError {
    fn from(_: ring::error::Unspecified) -> Self {
        CryptoError::RingUnspecified 
    }
}

impl From<std::string::FromUtf8Error> for CryptoError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        CryptoError::Utf8Error(e)
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(e: base64::DecodeError) -> Self {
        CryptoError::Base64Error(e)
    }
}

#[cfg(feature = "pq-crypto")]
/// This module provides functions for post-quantum cryptography using the pqcrypto library.
pub mod pqcrypto {
    use super::CryptoError;
    use pqcrypto_dilithium::dilithium2;
    use pqcrypto_kyber::kyber1024;
    use pqcrypto::traits::sign::SecretKey;
    use pqcrypto::traits::sign::PublicKey;
    use pqcrypto::traits::kem::PublicKey as pk;
    use pqcrypto::traits::kem::SecretKey as sk;
    use pqcrypto::traits::kem::SharedSecret;
    use pqcrypto::traits::kem::Ciphertext;
    use pqcrypto::traits::sign::SignedMessage;

    pub struct PQSignatureKeypair {
        pub public: Vec<u8>,
        pub secret: Vec<u8>,
    }

    /// Generate a new keypair for Dilithium signature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "pq-crypto")]
    /// # {
    /// let keypair = axial::pqcrypto::pq_sig_keypair();
    /// assert!(!keypair.public.is_empty());
    /// assert!(!keypair.secret.is_empty());
    /// # }
    /// ```
    pub fn pq_sig_keypair() -> PQSignatureKeypair {
        let (pk, sk) = dilithium2::keypair();
        PQSignatureKeypair {
            public: pk.as_bytes().to_vec(),
            secret: sk.as_bytes().to_vec(),
        }
    }

    /// Sign a message with a Dilithium secret key.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "pq-crypto")]
    /// # {
    /// let keypair = axial::pqcrypto::pq_sig_keypair();
    /// let message = b"This is a test message";
    /// let signature = axial::pqcrypto::pq_sign(message, &keypair.secret);
    /// assert!(!signature.is_empty());
    /// # }
    /// ```
    pub fn pq_sign(message: &[u8], secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = dilithium2::SecretKey::from_bytes(secret)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        let signed = dilithium2::sign(message, &sk);
        Ok(signed.as_bytes().to_vec())
    }

    /// Verify a Dilithium signature against a message and public key.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "pq-crypto")]
    /// # {
    /// let keypair = axial::pqcrypto::pq_sig_keypair();
    /// let message = b"This is a test message";
    /// let signature = axial::pqcrypto::pq_sign(message, &keypair.secret);
    /// let is_valid = axial::pqcrypto::pq_verify(message, &signature, &keypair.public);
    /// assert!(is_valid);
    ///
    /// let tampered_message = b"This is a tampered message";
    /// let is_invalid = axial::pqcrypto::pq_verify(tampered_message, &signature, &keypair.public);
    /// assert!(!is_invalid);
    /// # }
    /// ```
    pub fn pq_verify(message: &[u8], signed_message_bytes: &[u8], public: &[u8]) -> Result<bool, CryptoError> {
        let pk = dilithium2::PublicKey::from_bytes(public)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let signed_msg = dilithium2::SignedMessage::from_bytes(signed_message_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        match dilithium2::open(&signed_msg, &pk) {
            Ok(recovered_message) => Ok(recovered_message == message),
            Err(_) => Err(CryptoError::VerificationFailed),
        }
    }

    #[derive(Debug)]
    pub struct PQKEMKeypair {
        pub public: Vec<u8>,
        pub secret: Vec<u8>,
    }

    /// Generate a new keypair for Kyber KEM.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "pq-crypto")]
    /// # {
    /// let kem_keypair = axial::pqcrypto::pq_kem_keypair();
    /// assert!(!kem_keypair.public.is_empty());
    /// assert!(!kem_keypair.secret.is_empty());
    /// # }
    /// ```
    pub fn pq_kem_keypair() -> PQKEMKeypair {
        let (pk, sk) = kyber1024::keypair();
        PQKEMKeypair {
            public: pk.as_bytes().to_vec(),
            secret: sk.as_bytes().to_vec(),
        }
    }

    /// Encrypt/encapsulate a shared secret using Kyber KEM with a public key.
    /// Returns the Shared Secret and the CipherText.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "pq-crypto")]
    /// # {
    /// let kem_keypair = axial::pqcrypto::pq_kem_keypair();
    /// let (shared_secret_alice, ciphertext) = axial::pqcrypto::pq_kem_encapsulate(&kem_keypair.public).unwrap();
    /// assert!(!shared_secret_alice.is_empty());
    /// assert!(!ciphertext.is_empty());
    /// # }
    /// ```
    pub fn pq_kem_encapsulate(public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let pk = kyber1024::PublicKey::from_bytes(public)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let (ss, ct) = kyber1024::encapsulate(&pk);
        Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
    }

    /// Decrypt/decapsulate a ciphertext to retrieve a shared secret using Kyber KEM with a secret key.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "pq-crypto")]
    /// # {
    /// use pqcrypto::traits::kem::SharedSecret; // For as_bytes() on shared secret comparison
    /// let kem_keypair = axial::pqcrypto::pq_kem_keypair();
    /// let (ciphertext, shared_secret_alice) = axial::pqcrypto::pq_kem_encapsulate(&kem_keypair.public).unwrap();
    ///
    /// let shared_secret_bob = axial::pqcrypto::pq_kem_decapsulate(&kem_keypair.secret, &ciphertext).unwrap();
    /// assert_eq!(shared_secret_alice, shared_secret_bob);
    /// # }
    /// ```
    pub fn pq_kem_decapsulate(secret: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = kyber1024::SecretKey::from_bytes(secret)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let ss = kyber1024::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }

    /// Helper function that combines Kyber KEM encapsulation with AES key derivation
    /// 
    /// # Returns
    /// 
    /// A tuple containing:
    /// - `aes_key`: 32-byte key suitable for AES-256-GCM
    /// - `ciphertext`: The Kyber ciphertext that must be sent to the recipient
    pub fn kyber_derive_aes_key(recipient_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let (shared_secret, ciphertext) = pq_kem_encapsulate(recipient_public_key)?;

        let aes_key = derive_key_from_shared_secret(&shared_secret)?;
        
        Ok((aes_key, ciphertext))
    }

    /// Helper function that combines Kyber KEM decapsulation with AES key derivation
    pub fn kyber_recover_aes_key(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let shared_secret = pq_kem_decapsulate(private_key, ciphertext)?;
        let aes_key = derive_key_from_shared_secret(&shared_secret)?;
        Ok(aes_key)
    }

    /// Securely derives a key from a shared secret using HKDF
    fn derive_key_from_shared_secret(shared_secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use ring::hkdf;

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"kyber_aes_key_derivation_salt");
        let prk = salt.extract(shared_secret);
        
        let okm = prk.expand(&[b"encryption_key"], hkdf::HKDF_SHA256)
            .map_err(|_| CryptoError::InternalError("HKDF expansion failed".to_string()))?;
            
        let mut key_material = [0u8; 32];
        okm.fill(&mut key_material)
            .map_err(|_| CryptoError::InternalError("HKDF output material fill failed".to_string()))?;

        Ok(key_material.to_vec())
    }
}


/// Hash a &str using SHA256 and returns a hex-encoded string.
///
/// # Examples
///
/// ```
/// let hashed_text = axial::sha256("hello world");
/// assert_eq!(hashed_text, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
/// ```
pub fn sha256(text: &str) -> String {
    let hash = digest(&SHA256, text.as_bytes());
    hex::encode(hash)
}

/// Hash a &str using SHA512 and returns a hex-encoded string.
///
/// # Examples
///
/// ```
/// let hashed_text = axial::sha512("hello world");
/// assert_eq!(hashed_text, "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
/// ```
pub fn sha512(text: &str) -> String {
    let hash = digest(&SHA512, text.as_bytes());
    hex::encode(hash)
}

/// Hash a &str using SHA384 and returns a hex-encoded string.
///
/// # Examples
///
/// ```
/// let hashed_text = axial::sha384("hello world");
/// assert_eq!(hashed_text, "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af9eff145056ec89f71b843a9dbf048497e3b95cf9d24006");
/// ```
pub fn sha384(text: &str) -> String {
    let hash = digest(&SHA384, text.as_bytes());
    hex::encode(hash)
}

/// Derives a key from text using PBKDF2-HMAC-SHA256.
/// The provided `salt` slice is filled with random bytes by this function.
/// The caller must provide a `salt` slice of desired length (e.g., 16 bytes).
/// Returns the derived key as a base64 encoded string.
///
/// # Examples
///
/// ```
/// let mut salt = [0u8; 16]; // Provide a buffer for the salt
/// match axial::pbkdf2("mypassword", &mut salt) {
///     Ok(hashed_password_b64) => {
///         assert!(!hashed_password_b64.is_empty());
///         // `salt` now contains the generated salt, store it alongside hashed_password_b64
///         println!("Salt (hex): {}", hex::encode(salt));
///         println!("Hashed password (base64): {}", hashed_password_b64);
///     }
///     Err(e) => panic!("pbkdf2 failed: {}", e),
/// }
/// ```
pub fn pbkdf2(text: &str, salt: &mut [u8]) -> Result<String, CryptoError> {
    SystemRandom::new().fill(salt)?;
    let mut hash = [0u8; 32]; 
    let iterations = NonZeroU32::new(600_000)
        .ok_or(CryptoError::InternalError("Invalid PBKDF2 iteration count".to_string()))?;

    pbkdf2::derive(
        PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        text.as_bytes(),
        &mut hash,
    );

    Ok(general_purpose::STANDARD.encode(hash))
}

/// Verifies a password against a salt and an expected hash (raw bytes) using PBKDF2-HMAC-SHA256.
///
/// # Examples
///
/// ```
/// use base64::Engine; // For decoding if the stored hash is base64
/// use base64::engine::general_purpose;
///
/// let password_to_check = "mypassword";
/// let mut stored_salt = [0u8; 16]; // Assume this was filled and stored previously
///
/// // Scenario 1: Simulating a stored salt and base64 encoded hash
/// // First, generate a hash and salt like the `pbkdf2` function would
/// let original_salt_for_generation = &mut [0u8; 16];
/// ring::rand::SystemRandom::new().fill(original_salt_for_generation).unwrap();
/// let generated_hash_b64 = axial::pbkdf2(password_to_check, original_salt_for_generation).unwrap();
///
/// // Now, to verify, we need the raw hash bytes.
/// let stored_hash_bytes = general_purpose::STANDARD.decode(generated_hash_b64).unwrap();
/// stored_salt.copy_from_slice(original_salt_for_generation); // Use the salt that was generated
///
/// let is_valid = axial::pbkdf2_verify(password_to_check, &stored_salt, &stored_hash_bytes).unwrap();
/// assert!(is_valid);
///
/// let is_invalid = axial::pbkdf2_verify("wrongpassword", &stored_salt, &stored_hash_bytes).unwrap();
/// assert!(!is_invalid);
/// ```
pub fn pbkdf2_verify(password: &str, salt: &[u8], expected_hash: &[u8]) -> Result<(), CryptoError> {
    let iterations = NonZeroU32::new(600_000)
        .ok_or(CryptoError::InternalError("Invalid PBKDF2 iteration count for verify".to_string()))?;
    pbkdf2::verify(
        PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        expected_hash,
    )
    .map_err(|_| CryptoError::VerificationFailed)?;
    Ok(())
}

#[derive(Debug)]
pub struct Crypto {
    pub key: Vec<u8>,
}

impl Crypto {
    /// Creates a new `Crypto` instance with the given key.
    /// Key length must be 16 bytes (for AES-128-GCM) or 32 bytes (for AES-256-GCM).
    ///
    /// # Examples
    ///
    /// ```
    /// let key16 = vec![0u8; 16];
    /// let crypto128 = axial::Crypto::new(key16).unwrap();
    ///
    /// let key32 = vec![0u8; 32];
    /// let crypto256 = axial::Crypto::new(key32).unwrap();
    ///
    /// let invalid_key = vec![0u8; 10];
    /// assert!(axial::Crypto::new(invalid_key).is_err());
    /// ```
    pub fn new(key: Vec<u8>) -> Result<Self, CryptoError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        Ok(Self { key })
    }

    /// Encrypts plaintext using AES-GCM (128 or 256 based on key length).
    /// The nonce is randomly generated and prepended to the ciphertext.
    /// The result is base64 encoded.
    ///
    /// # Examples
    ///
    /// ```
    /// let key = vec![0u8; 32]; // AES-256-GCM
    /// let crypto = axial::Crypto::new(key).unwrap();
    /// let plaintext = "hello symmetric encryption";
    ///
    /// match crypto.encrypt(plaintext) {
    ///     Ok(ciphertext_b64) => {
    ///         assert!(!ciphertext_b64.is_empty());
    ///         println!("Encrypted (base64): {}", ciphertext_b64);
    ///     }
    ///     Err(e) => panic!("Encryption failed: {}", e),
    /// }
    /// ```
    pub fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        let alg = match self.key.len() {
            16 => &AES_128_GCM,
            32 => &AES_256_GCM,
            _ => return Err(CryptoError::InternalError("Key length check failed post-construction".to_string())),
        };

        let unbound_key = UnboundKey::new(alg, &self.key)?;
        let key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce_bytes)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionError)?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);

        Ok(Engine::encode(&base64::engine::general_purpose::STANDARD, &result))
    }

    /// Decrypts a base64 encoded ciphertext (which includes prepended nonce and tag)
    /// using AES-GCM (128 or 256 based on key length).
    ///
    /// # Examples
    ///
    /// ```
    /// let key = vec![0u8; 16]; // AES-128-GCM
    /// let crypto = axial::Crypto::new(key).unwrap();
    /// let plaintext = "secret message!";
    ///
    /// let ciphertext_b64 = crypto.encrypt(plaintext).unwrap();
    ///
    /// match crypto.decrypt(&ciphertext_b64) {
    ///     Ok(decrypted_text) => {
    ///         assert_eq!(decrypted_text, plaintext);
    ///         println!("Decrypted: {}", decrypted_text);
    ///     }
    ///     Err(e) => panic!("Decryption failed: {}", e),
    /// }
    ///
    /// let tampered_ciphertext_b64 = "tamperedZmFrZQ=="; // Invalid/tampered data
    /// assert!(crypto.decrypt(tampered_ciphertext_b64).is_err());
    /// ```
    pub fn decrypt(&self, ciphertext_b64: &str) -> Result<String, CryptoError> {
        let alg = match self.key.len() {
            16 => &AES_128_GCM,
            32 => &AES_256_GCM,
            _ => return Err(CryptoError::InternalError("Key length check failed post-construction for decrypt".to_string())),
        };

        let unbound_key = UnboundKey::new(alg, &self.key)?;
        let key = LessSafeKey::new(unbound_key);

        let data = Engine::decode(&base64::engine::general_purpose::STANDARD, ciphertext_b64)?;

        if data.len() < NONCE_LEN {
            return Err(CryptoError::InvalidLength("Ciphertext too short to contain nonce".to_string()));
        }

        let (nonce_bytes_slice, ciphertext_and_tag) = data.split_at(NONCE_LEN);
        
        let nonce_array = <[u8; NONCE_LEN]>::try_from(nonce_bytes_slice)
            .map_err(|_| CryptoError::InvalidNonce)?;
        let nonce = Nonce::assume_unique_for_key(nonce_array);

        let mut binding = ciphertext_and_tag.to_vec();
        let decrypted_bytes_slice = key
            .open_in_place(nonce, Aad::empty(), &mut binding)
            .map_err(|_| CryptoError::DecryptionError)?;

        Ok(String::from_utf8(decrypted_bytes_slice.to_vec())?)
    }

    /// Encrypts plaintext using AES-GCM with additional authenticated data (AAD).
    /// 
    /// # Arguments
    /// 
    /// * `plaintext` - The text to encrypt
    /// * `aad` - Additional authenticated data that will be authenticated but not encrypted
    /// 
    /// # Returns
    /// 
    /// Base64-encoded string containing the nonce and ciphertext
    pub fn encrypt_with_aad(&self, plaintext: &str, aad: &[u8]) -> Result<String, CryptoError> {
        let alg = match self.key.len() {
            16 => &AES_128_GCM,
            32 => &AES_256_GCM,
            _ => return Err(CryptoError::InternalError("Invalid key length".to_string())),
        };

        let unbound_key = UnboundKey::new(alg, &self.key)?;
        let key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce_bytes)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::EncryptionError)?;

        let mut result = nonce_bytes.to_vec();

        let aad_len_bytes = (aad.len() as u32).to_be_bytes();
        result.extend_from_slice(&aad_len_bytes);

        result.extend_from_slice(aad);

        result.extend_from_slice(&in_out);

        Ok(Engine::encode(&base64::engine::general_purpose::STANDARD, &result))
    }

    /// Decrypts a base64 encoded ciphertext with AAD.
    /// 
    /// # Arguments
    /// 
    /// * `ciphertext_b64` - Base64-encoded string containing nonce, AAD and ciphertext
    /// 
    /// # Returns
    /// 
    /// The decrypted plaintext and the AAD that was authenticated
    pub fn decrypt_with_aad(&self, ciphertext_b64: &str) -> Result<(String, Vec<u8>), CryptoError> {
        let alg = match self.key.len() {
            16 => &AES_128_GCM,
            32 => &AES_256_GCM,
            _ => return Err(CryptoError::InternalError("Invalid key length".to_string())),
        };

        let unbound_key = UnboundKey::new(alg, &self.key)?;
        let key = LessSafeKey::new(unbound_key);

        let data = Engine::decode(&base64::engine::general_purpose::STANDARD, ciphertext_b64)?;

        if data.len() < NONCE_LEN + 4 {
            return Err(CryptoError::InvalidLength("Ciphertext too short".to_string()));
        }

        let (nonce_bytes_slice, remaining) = data.split_at(NONCE_LEN);
        let nonce = Nonce::assume_unique_for_key(
            <[u8; NONCE_LEN]>::try_from(nonce_bytes_slice).map_err(|_| CryptoError::InvalidNonce)?
        );

        let (aad_len_bytes, remaining) = remaining.split_at(4);
        let aad_len = u32::from_be_bytes(
            <[u8; 4]>::try_from(aad_len_bytes).map_err(|_| CryptoError::InvalidFormat("Invalid AAD length".to_string()))?
        ) as usize;

        if remaining.len() < aad_len {
            return Err(CryptoError::InvalidLength("AAD length exceeds data".to_string()));
        }

        let (aad, ciphertext_and_tag) = remaining.split_at(aad_len);
        
        let mut binding = ciphertext_and_tag.to_vec();
        let decrypted_bytes_slice = key
            .open_in_place(nonce, Aad::from(aad), &mut binding)
            .map_err(|_| CryptoError::DecryptionError)?;

        let plaintext = String::from_utf8(decrypted_bytes_slice.to_vec())?;
        
        Ok((plaintext, aad.to_vec()))
    }

    /// Zeroizes the key material in the Crypto instance.
    pub fn zeroize(&mut self) {
        for byte in self.key.iter_mut() {
            *byte = 0;
        }
    }
}

/// Modern password hashing with configurable parameters
pub struct PasswordHasher {
    iterations: NonZeroU32,
    hash_len: usize,
}

impl PasswordHasher {
    /// Creates a new password hasher with default secure parameters
    pub fn new() -> Self {
        Self {
            iterations: NonZeroU32::new(600_000).unwrap(),
            hash_len: 32,
        }
    }
    
    /// Set iteration count (minimum 100,000 enforced)
    pub fn with_iterations(mut self, iterations: u32) -> Result<Self, CryptoError> {
        const MIN_ITERATIONS: u32 = 100_000;
        
        if iterations < MIN_ITERATIONS {
            return Err(CryptoError::InvalidInput(
                format!("Iteration count must be at least {}", MIN_ITERATIONS)
            ));
        }
        
        self.iterations = NonZeroU32::new(iterations)
            .ok_or(CryptoError::InvalidInput("Iteration count cannot be zero".to_string()))?;
            
        Ok(self)
    }
    
    /// Set hash output length
    pub fn with_hash_len(mut self, hash_len: usize) -> Result<Self, CryptoError> {
        if hash_len < 16 || hash_len > 64 {
            return Err(CryptoError::InvalidInput("Hash length must be between 16 and 64 bytes".to_string()));
        }
        self.hash_len = hash_len;
        Ok(self)
    }
    
    /// Hash a password with a randomly generated salt
    pub fn hash_password(&self, password: &str, salt: &mut [u8]) -> Result<Vec<u8>, CryptoError> {
        if salt.len() < 16 {
            return Err(CryptoError::InvalidInput("Salt must be at least 16 bytes".to_string()));
        }

        SystemRandom::new().fill(salt)?;

        let mut hash = vec![0u8; self.hash_len];

        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            self.iterations,
            salt,
            password.as_bytes(),
            &mut hash,
        );
        
        Ok(hash)
    }
    
    /// Verify a password against stored hash and salt
    pub fn verify_password(&self, password: &str, salt: &[u8], expected_hash: &[u8]) -> Result<bool, CryptoError> {
        if salt.len() < 16 {
            return Err(CryptoError::InvalidInput("Salt must be at least 16 bytes".to_string()));
        }
        
        let result = pbkdf2::verify(
            PBKDF2_HMAC_SHA256,
            self.iterations,
            salt,
            password.as_bytes(),
            expected_hash,
        );
        
        Ok(result.is_ok())
    }
}

/// Constant-time equality comparison to prevent timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

pub struct HybridCrypto;

impl HybridCrypto {
    /// Ecnrypt the message using the Kyber public key
    /// 
    /// # Returns
    /// 
    /// * `kyber_ciphertext` - Ciphertext Kyber for key exchange
    /// * `encrypted_data` - Encrypted data with AES
    pub fn encrypt(
        recipient_public_key: &[u8],
        plaintext: &str,
        aad: Option<&[u8]>
    ) -> Result<(Vec<u8>, String), CryptoError> {
        let (mut aes_key, kyber_ciphertext) = pqcrypto::kyber_derive_aes_key(recipient_public_key)?;

        let crypto = Crypto::new(aes_key.clone())?;

        let encrypted_data = match aad {
            Some(aad_data) => crypto.encrypt_with_aad(plaintext, aad_data)?,
            None => crypto.encrypt(plaintext)?,
        };

        for byte in aes_key.iter_mut() {
            *byte = 0;
        }
        
        Ok((kyber_ciphertext, encrypted_data))
    }
    
    /// Decrypt the message using the Kyber private key
    pub fn decrypt(
        private_key: &[u8],
        kyber_ciphertext: &[u8],
        encrypted_data: &str,
        has_aad: bool
    ) -> Result<(String, Option<Vec<u8>>), CryptoError> {
        let mut aes_key = pqcrypto::kyber_recover_aes_key(private_key, kyber_ciphertext)?;

        let crypto = Crypto::new(aes_key.clone())?;

        let result = if has_aad {
            let (plaintext, aad) = crypto.decrypt_with_aad(encrypted_data)?;
            (plaintext, Some(aad))
        } else {
            (crypto.decrypt(encrypted_data)?, None)
        };

        for byte in aes_key.iter_mut() {
            *byte = 0;
        }
        
        Ok(result)
    }
}

/// Secure container for cryptographic keys
pub struct SecureKey {
    key_data: Vec<u8>,
    key_type: KeyType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    Aes128,
    Aes256,
    KyberPublic,
    KyberPrivate,
    DilithiumPublic,
    DilithiumPrivate,
}

impl SecureKey {
    /// Create a new secure key with type and size validation
    pub fn new(key_data: Vec<u8>, key_type: KeyType) -> Result<Self, CryptoError> {
        match key_type {
            KeyType::Aes128 if key_data.len() != 16 =>
                return Err(CryptoError::InvalidKeyLength),
            KeyType::Aes256 if key_data.len() != 32 =>
                return Err(CryptoError::InvalidKeyLength),
            KeyType::KyberPublic if key_data.len() != 1568 =>
                return Err(CryptoError::InvalidPublicKey),
            KeyType::KyberPrivate if key_data.len() != 3168 =>
                return Err(CryptoError::InvalidPrivateKey),
            _ => {}
        }
        
        Ok(Self { key_data, key_type })
    }
    
    /// Safety access to the key data
    pub fn with_key<F, R>(&self, operation: F) -> R 
    where 
        F: FnOnce(&[u8]) -> R 
    {
        operation(&self.key_data)
    }
    
    /// Returns the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
    
    /// Safety zeroizes the key data
    pub fn zeroize(&mut self) {
        for byte in self.key_data.iter_mut() {
            *byte = 0;
        }
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}