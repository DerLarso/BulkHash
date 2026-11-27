use std::fmt;
use std::io::{Read, Write};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use zeroize::Zeroizing;

use crate::core::io::bulk_hash_error::BulkHashError;

/// ZIP archive entry name for encrypted directory trees in `.hashed` format v3+.
pub const ENCRYPTED_TREE_ENTRY: &str = "tree.enc";

/// Derived symmetric key length in bytes (256-bit key for AES-256-GCM).
pub const AES_256_KEY_LEN: usize = 32;

/// Nonce length in bytes (96-bit standard NIST SP 800-38D nonce for AES-GCM).
pub const AES_GCM_NONCE_LEN: usize = 12;

/// Authentication tag length in bytes (128-bit GCM tag).
pub const AES_GCM_TAG_LEN: usize = 16;

/// Salt length in bytes generated for Argon2id key derivation (128-bit salt, RFC 9106).
pub const KDF_SALT_LEN: usize = 16;

/// Minimum accepted KDF salt length in bytes when validating an encrypted archive.
pub const MIN_KDF_SALT_LEN: usize = 16;

/// Maximum accepted KDF salt length in bytes when validating an encrypted archive.
pub const MAX_KDF_SALT_LEN: usize = 64;

/// Minimum allowed Argon2id memory cost in KiB (64 KiB).
pub const MIN_KDF_MEMORY_KIB: u32 = 64;

/// Maximum allowed Argon2id memory cost in KiB (1 GiB) to protect against OOM DoS
/// from maliciously crafted `.hashed` archives.
pub const MAX_KDF_MEMORY_KIB: u32 = 1_048_576;

/// Minimum allowed Argon2id iteration count.
pub const MIN_KDF_ITERATIONS: u32 = 1;

/// Maximum allowed Argon2id iteration count to protect against CPU-exhaustion DoS
/// from maliciously crafted `.hashed` archives.
pub const MAX_KDF_ITERATIONS: u32 = 32;

/// Minimum allowed Argon2id parallelism (lanes).
pub const MIN_KDF_PARALLELISM: u32 = 1;

/// Maximum allowed Argon2id parallelism (lanes).
pub const MAX_KDF_PARALLELISM: u32 = 16;

const TREE_AAD_DOMAIN_PREFIX: &[u8] = b"BulkHash:tree.enc:aead:v1\0";

/// Supported authenticated encryption ciphers for `.hashed` snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum EncryptionCipher {
    /// AES-256-GCM (256-bit key, 96-bit nonce, 128-bit authentication tag).
    #[default]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

impl fmt::Display for EncryptionCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes256Gcm => f.write_str("aes-256-gcm"),
        }
    }
}

/// Supported password-based key derivation functions for `.hashed` snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum KeyDerivationAlgorithm {
    /// Argon2id v0x13 (RFC 9106 memory-hard key derivation).
    #[default]
    #[serde(rename = "argon2id")]
    Argon2id,
}

impl fmt::Display for KeyDerivationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argon2id => f.write_str("argon2id"),
        }
    }
}

/// Compression applied to the serialized `tree.json` plaintext before AEAD encryption.
///
/// Ciphertext is indistinguishable from uniform random bytes and cannot be compressed
/// effectively by the outer ZIP layer, so compressing before encryption preserves
/// compact `.hashed` file sizes while storing `tree.enc` uncompressed (`Stored`) in ZIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum PayloadCompression {
    /// Encrypt raw UTF-8 `tree.json` bytes without inner compression.
    #[serde(rename = "none")]
    None,
    /// Compress `tree.json` with raw DEFLATE prior to AES-256-GCM encryption (default).
    #[default]
    #[serde(rename = "deflate")]
    Deflate,
}

impl fmt::Display for PayloadCompression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Deflate => f.write_str("deflate"),
        }
    }
}

/// Argon2id cost parameters controlling memory hardness, iterations, and parallelism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory size in KiB (e.g., `65_536` = 64 MiB).
    pub memory_kib: u32,
    /// Number of Argon2id passes / iterations (time cost).
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::standard()
    }
}

impl KdfParams {
    /// Standard interactive desktop preset (RFC 9106): 64 MiB memory, 3 iterations, 4 lanes.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 4,
        }
    }

    /// Lighter OWASP-recommended interactive preset for low-RAM devices: 19 MiB, 2 iterations, 1 lane.
    #[must_use]
    pub const fn interactive() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }

    /// High-security archival preset: 128 MiB memory, 4 iterations, 4 lanes.
    #[must_use]
    pub const fn high() -> Self {
        Self {
            memory_kib: 131_072,
            iterations: 4,
            parallelism: 4,
        }
    }

    /// Creates custom Argon2id parameters after enforcing safety and DoS-prevention bounds.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidEncryptionParameters`] if any parameter is outside
    /// the supported bounds or violates Argon2's `memory_kib >= 8 * parallelism` invariant.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, BulkHashError> {
        let params = Self {
            memory_kib,
            iterations,
            parallelism,
        };
        params.validate()?;
        Ok(params)
    }

    /// Validates that these parameters lie within safe cryptographic and DoS-prevention bounds.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidEncryptionParameters`] if any parameter is invalid.
    pub fn validate(&self) -> Result<(), BulkHashError> {
        if self.memory_kib < MIN_KDF_MEMORY_KIB || self.memory_kib > MAX_KDF_MEMORY_KIB {
            return Err(BulkHashError::InvalidEncryptionParameters(format!(
                "Argon2id memory_kib ({}) must be between {MIN_KDF_MEMORY_KIB} and {MAX_KDF_MEMORY_KIB}",
                self.memory_kib
            )));
        }

        if self.iterations < MIN_KDF_ITERATIONS || self.iterations > MAX_KDF_ITERATIONS {
            return Err(BulkHashError::InvalidEncryptionParameters(format!(
                "Argon2id iterations ({}) must be between {MIN_KDF_ITERATIONS} and {MAX_KDF_ITERATIONS}",
                self.iterations
            )));
        }

        if self.parallelism < MIN_KDF_PARALLELISM || self.parallelism > MAX_KDF_PARALLELISM {
            return Err(BulkHashError::InvalidEncryptionParameters(format!(
                "Argon2id parallelism ({}) must be between {MIN_KDF_PARALLELISM} and {MAX_KDF_PARALLELISM}",
                self.parallelism
            )));
        }

        let min_for_lanes = self.parallelism.saturating_mul(8);
        if self.memory_kib < min_for_lanes {
            return Err(BulkHashError::InvalidEncryptionParameters(format!(
                "Argon2id memory_kib ({}) must be at least 8 * parallelism ({min_for_lanes})",
                self.memory_kib
            )));
        }

        Ok(())
    }
}

/// Public (non-secret) encryption descriptor stored in `meta.json` for encrypted `.hashed` snapshots.
///
/// The full raw `meta.json` bytes (including this struct) are cryptographically bound into
/// the AES-256-GCM authentication tag as Associated Authenticated Data (AAD), preventing
/// tampering or parameter downgrade attacks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EncryptionMetadata {
    pub cipher: EncryptionCipher,
    pub kdf: KeyDerivationAlgorithm,
    pub kdf_params: KdfParams,
    /// Standard Base64-encoded random KDF salt.
    pub salt: String,
    /// Standard Base64-encoded 96-bit random AES-GCM nonce.
    pub nonce: String,
    #[serde(default)]
    pub payload_compression: PayloadCompression,
}

impl EncryptionMetadata {
    /// Generates fresh encryption metadata with cryptographically secure random salt and nonce
    /// from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidEncryptionParameters`] if `kdf_params` are out of bounds,
    /// or [`BulkHashError::EncryptionFailed`] if OS randomness generation fails.
    pub fn generate(
        kdf_params: KdfParams,
        payload_compression: PayloadCompression,
    ) -> Result<Self, BulkHashError> {
        kdf_params.validate()?;

        let mut salt = [0u8; KDF_SALT_LEN];
        getrandom::fill(&mut salt).map_err(|err| {
            BulkHashError::EncryptionFailed(format!("failed to generate random KDF salt: {err}"))
        })?;

        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|err| {
            BulkHashError::EncryptionFailed(format!("failed to generate random AES-GCM nonce: {err}"))
        })?;

        Ok(Self {
            cipher: EncryptionCipher::Aes256Gcm,
            kdf: KeyDerivationAlgorithm::Argon2id,
            kdf_params,
            salt: BASE64_STANDARD.encode(salt),
            nonce: BASE64_STANDARD.encode(nonce),
            payload_compression,
        })
    }

    /// Validates all parameters, Base64 encodings, and decoded byte lengths.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidEncryptionParameters`] if any field is invalid.
    pub fn validate(&self) -> Result<(), BulkHashError> {
        self.kdf_params.validate()?;
        let _ = self.decode_salt()?;
        let _ = self.decode_nonce()?;
        Ok(())
    }

    /// Decodes and validates the KDF salt bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidEncryptionParameters`] if `salt` is not valid Base64
    /// or its decoded byte length is outside [`MIN_KDF_SALT_LEN`]..=[`MAX_KDF_SALT_LEN`].
    pub fn decode_salt(&self) -> Result<Vec<u8>, BulkHashError> {
        let salt = BASE64_STANDARD.decode(&self.salt).map_err(|err| {
            BulkHashError::InvalidEncryptionParameters(format!("invalid Base64 salt: {err}"))
        })?;

        if salt.len() < MIN_KDF_SALT_LEN || salt.len() > MAX_KDF_SALT_LEN {
            return Err(BulkHashError::InvalidEncryptionParameters(format!(
                "salt length ({} bytes) must be between {MIN_KDF_SALT_LEN} and {MAX_KDF_SALT_LEN} bytes",
                salt.len()
            )));
        }

        Ok(salt)
    }

    /// Decodes and validates the 96-bit AES-GCM nonce bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidEncryptionParameters`] if `nonce` is not valid Base64
    /// or does not decode to exactly [`AES_GCM_NONCE_LEN`] (12) bytes.
    pub fn decode_nonce(&self) -> Result<[u8; AES_GCM_NONCE_LEN], BulkHashError> {
        let nonce_vec = BASE64_STANDARD.decode(&self.nonce).map_err(|err| {
            BulkHashError::InvalidEncryptionParameters(format!("invalid Base64 nonce: {err}"))
        })?;

        <[u8; AES_GCM_NONCE_LEN]>::try_from(nonce_vec.as_slice()).map_err(|_| {
            BulkHashError::InvalidEncryptionParameters(format!(
                "AES-GCM nonce length ({} bytes) must be exactly {AES_GCM_NONCE_LEN} bytes",
                nonce_vec.len()
            ))
        })
    }
}

/// Caller-supplied options for encrypting a `.hashed` snapshot.
///
/// The password is stored inside a [`Zeroizing`] buffer so it is scrubbed from memory on drop,
/// and [`fmt::Debug`] always redacts it.
#[derive(Clone)]
pub struct EncryptionOptions {
    password: Zeroizing<String>,
    kdf_params: KdfParams,
    payload_compression: PayloadCompression,
}

impl fmt::Debug for EncryptionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionOptions")
            .field("password", &"[REDACTED]")
            .field("kdf_params", &self.kdf_params)
            .field("payload_compression", &self.payload_compression)
            .finish()
    }
}

impl EncryptionOptions {
    /// Creates encryption options with [`KdfParams::standard()`] and [`PayloadCompression::Deflate`].
    ///
    /// Note that passwords are used verbatim (never trimmed) so passphrases with intentional
    /// leading or trailing spaces work consistently.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::EmptyPassword`] if `password` is empty.
    pub fn new(password: impl Into<String>) -> Result<Self, BulkHashError> {
        let password = Zeroizing::new(password.into());
        if password.is_empty() {
            return Err(BulkHashError::EmptyPassword);
        }

        Ok(Self {
            password,
            kdf_params: KdfParams::standard(),
            payload_compression: PayloadCompression::Deflate,
        })
    }

    /// Overrides the Argon2id key derivation parameters after validating safety bounds.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidEncryptionParameters`] if `kdf_params` are invalid.
    pub fn with_kdf_params(mut self, kdf_params: KdfParams) -> Result<Self, BulkHashError> {
        kdf_params.validate()?;
        self.kdf_params = kdf_params;
        Ok(self)
    }

    /// Configures whether the tree JSON plaintext is compressed before AES-256-GCM encryption.
    #[must_use]
    pub const fn with_payload_compression(mut self, compression: PayloadCompression) -> Self {
        self.payload_compression = compression;
        self
    }

    #[must_use]
    pub const fn kdf_params(&self) -> KdfParams {
        self.kdf_params
    }

    #[must_use]
    pub const fn payload_compression(&self) -> PayloadCompression {
        self.payload_compression
    }

    /// Validates that these options contain a non-empty password and valid KDF parameters.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::EmptyPassword`] or [`BulkHashError::InvalidEncryptionParameters`].
    pub fn validate(&self) -> Result<(), BulkHashError> {
        if self.password.is_empty() {
            return Err(BulkHashError::EmptyPassword);
        }
        self.kdf_params.validate()
    }

    #[must_use]
    pub(crate) fn password(&self) -> &str {
        self.password.as_str()
    }
}

/// Generates fresh [`EncryptionMetadata`] (with brand-new random salt and nonce) for saving an
/// encrypted snapshot with `options`.
///
/// # Errors
///
/// Returns an error if `options` are invalid or the OS CSPRNG fails.
pub fn prepare_encryption_metadata(
    options: &EncryptionOptions,
) -> Result<EncryptionMetadata, BulkHashError> {
    options.validate()?;
    EncryptionMetadata::generate(options.kdf_params(), options.payload_compression())
}

/// Parses and validates an [`EncryptionMetadata`] header from a parsed `meta.json` JSON value.
///
/// # Errors
///
/// Returns [`BulkHashError::InvalidEncryptionParameters`] if the JSON structure is malformed,
/// specifies an unsupported cipher/KDF, or contains invalid KDF/salt/nonce values.
pub fn parse_encryption_metadata(
    value: &serde_json::Value,
) -> Result<EncryptionMetadata, BulkHashError> {
    let metadata: EncryptionMetadata = serde_json::from_value(value.clone()).map_err(|err| {
        BulkHashError::InvalidEncryptionParameters(format!(
            "malformed 'encryption' metadata: {err}"
        ))
    })?;
    metadata.validate()?;
    Ok(metadata)
}

/// Builds domain-separated Associated Authenticated Data (AAD) binding the archive format version
/// and exact `meta.json` bytes into the AES-256-GCM authentication tag.
#[must_use]
pub fn build_tree_aad(format_version: usize, meta_json_bytes: &[u8]) -> Vec<u8> {
    let version_be = (format_version as u64).to_be_bytes();
    let mut aad = Vec::with_capacity(
        TREE_AAD_DOMAIN_PREFIX.len() + version_be.len() + meta_json_bytes.len(),
    );
    aad.extend_from_slice(TREE_AAD_DOMAIN_PREFIX);
    aad.extend_from_slice(&version_be);
    aad.extend_from_slice(meta_json_bytes);
    aad
}

/// Derives a 256-bit symmetric key from `password` and `metadata` using Argon2id v0x13.
///
/// The returned key is wrapped in [`Zeroizing`] so it is automatically scrubbed on drop.
///
/// # Errors
///
/// Returns [`BulkHashError::EmptyPassword`], [`BulkHashError::InvalidEncryptionParameters`],
/// or [`BulkHashError::EncryptionFailed`] if derivation fails.
pub fn derive_key(
    password: &str,
    metadata: &EncryptionMetadata,
) -> Result<Zeroizing<[u8; AES_256_KEY_LEN]>, BulkHashError> {
    if password.is_empty() {
        return Err(BulkHashError::EmptyPassword);
    }

    metadata.validate()?;
    let salt = metadata.decode_salt()?;

    match metadata.kdf {
        KeyDerivationAlgorithm::Argon2id => {
            let params = Params::new(
                metadata.kdf_params.memory_kib,
                metadata.kdf_params.iterations,
                metadata.kdf_params.parallelism,
                Some(AES_256_KEY_LEN),
            )
            .map_err(|err| {
                BulkHashError::InvalidEncryptionParameters(format!(
                    "invalid Argon2id parameters: {err}"
                ))
            })?;

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = Zeroizing::new([0u8; AES_256_KEY_LEN]);
            argon2
                .hash_password_into(password.as_bytes(), &salt, key.as_mut())
                .map_err(|err| {
                    BulkHashError::EncryptionFailed(format!("Argon2id key derivation failed: {err}"))
                })?;

            Ok(key)
        }
    }
}

/// Encrypts `plaintext_tree_json` using AES-256-GCM with an Argon2id-derived key and AAD.
///
/// Intermediate plaintext compression buffers and the derived key are zeroized on drop.
///
/// # Errors
///
/// Returns an error if `options` or `metadata` are invalid, compression fails, key derivation
/// fails, or AES-256-GCM encryption fails.
pub fn encrypt_tree_payload(
    plaintext_tree_json: &[u8],
    options: &EncryptionOptions,
    metadata: &EncryptionMetadata,
    aad: &[u8],
) -> Result<Vec<u8>, BulkHashError> {
    metadata.validate()?;
    let nonce_bytes = metadata.decode_nonce()?;
    let key = derive_key(options.password(), metadata)?;

    let compressed_buf: Option<Zeroizing<Vec<u8>>> = match metadata.payload_compression {
        PayloadCompression::None => None,
        PayloadCompression::Deflate => {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(plaintext_tree_json).map_err(|err| {
                BulkHashError::EncryptionFailed(format!(
                    "failed to compress tree payload prior to encryption: {err}"
                ))
            })?;
            let compressed = encoder.finish().map_err(|err| {
                BulkHashError::EncryptionFailed(format!(
                    "failed to finalize compressed tree payload: {err}"
                ))
            })?;
            Some(Zeroizing::new(compressed))
        }
    };

    let msg: &[u8] = compressed_buf
        .as_deref()
        .map_or(plaintext_tree_json, Vec::as_slice);

    match metadata.cipher {
        EncryptionCipher::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| {
                BulkHashError::EncryptionFailed(String::from("failed to initialize AES-256-GCM"))
            })?;
            let nonce = Nonce::from(nonce_bytes);
            cipher
                .encrypt(&nonce, Payload { msg, aad })
                .map_err(|_| {
                    BulkHashError::EncryptionFailed(String::from("AES-256-GCM encryption failed"))
                })
        }
    }
}

/// Decrypts `ciphertext` using AES-256-GCM with an Argon2id-derived key and verifies `aad`,
/// then transparently decompresses the payload (with strict `max_plaintext_bytes` protection).
///
/// # Errors
///
/// Returns:
/// - [`BulkHashError::EmptyPassword`] if `password` is empty,
/// - [`BulkHashError::InvalidEncryptionParameters`] if `metadata` is invalid,
/// - [`BulkHashError::FileIsCorrupted`] if ciphertext is shorter than the GCM tag or
///   decompression fails / exceeds `max_plaintext_bytes`,
/// - [`BulkHashError::DecryptionFailed`] if authentication fails (wrong password or tampered data).
pub fn decrypt_tree_payload(
    ciphertext: &[u8],
    password: &str,
    metadata: &EncryptionMetadata,
    aad: &[u8],
    max_plaintext_bytes: u64,
    source_label: &str,
) -> Result<Zeroizing<Vec<u8>>, BulkHashError> {
    if password.is_empty() {
        return Err(BulkHashError::EmptyPassword);
    }

    metadata.validate()?;

    if ciphertext.len() < AES_GCM_TAG_LEN {
        return Err(BulkHashError::FileIsCorrupted(format!(
            "{source_label}: encrypted tree payload is truncated ({} bytes, minimum {AES_GCM_TAG_LEN})",
            ciphertext.len()
        )));
    }

    let nonce_bytes = metadata.decode_nonce()?;
    let key = derive_key(password, metadata)?;

    let decrypted = match metadata.cipher {
        EncryptionCipher::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| {
                BulkHashError::EncryptionFailed(String::from("failed to initialize AES-256-GCM"))
            })?;
            let nonce = Nonce::from(nonce_bytes);
            let plain = cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| BulkHashError::DecryptionFailed(source_label.to_owned()))?;
            Zeroizing::new(plain)
        }
    };

    match metadata.payload_compression {
        PayloadCompression::None => {
            if (decrypted.len() as u64) > max_plaintext_bytes {
                return Err(BulkHashError::FileIsCorrupted(format!(
                    "{source_label}: decrypted tree exceeds maximum allowed size"
                )));
            }
            Ok(decrypted)
        }
        PayloadCompression::Deflate => {
            let mut decoder = DeflateDecoder::new(decrypted.as_slice());
            let mut decompressed = Zeroizing::new(Vec::new());
            decoder
                .by_ref()
                .take(max_plaintext_bytes.saturating_add(1))
                .read_to_end(&mut decompressed)
                .map_err(|err| {
                    BulkHashError::FileIsCorrupted(format!(
                        "{source_label}: failed to decompress decrypted tree payload: {err}"
                    ))
                })?;

            if (decompressed.len() as u64) > max_plaintext_bytes {
                return Err(BulkHashError::FileIsCorrupted(format!(
                    "{source_label}: decompressed tree exceeds maximum allowed size"
                )));
            }

            Ok(decompressed)
        }
    }
}
