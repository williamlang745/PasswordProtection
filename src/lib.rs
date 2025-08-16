//! Simple password-based encryption using AES-256-GCM and PBKDF2-HMAC-SHA256.
//!
//! This module provides two functions:
//! - [`lock_data`] → encrypts and authenticates data with a password.
//! - [`unlock_data`] → decrypts and verifies the ciphertext with the same password.
//!
//! Format of output (protected data):
//! ```text
//! [ salt (16 bytes) | nonce (12 bytes) | ciphertext+tag (N bytes) ]
//! ```

use aes_gcm::{Aes256Gcm, KeyInit, Nonce}; // AES-GCM cipher
use aes_gcm::aead::{Aead, OsRng};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

/// Number of PBKDF2 iterations (security vs performance trade-off).
const PBKDF2_ITERS: u32 = 100_000;
/// Salt length in bytes (randomized each time).
const SALT_LEN: usize = 16;
/// AES-GCM standard nonce length.
const NONCE_LEN: usize = 12;
/// AES-GCM 256 key size in bytes.
const AES_GCM_256_KEY_SIZE: usize = 32;

/// Encrypts data with a password, returning `[salt | nonce | ciphertext+tag]`.
///
/// # Errors
/// Panics if AES key/nonce initialization fails (should not happen with valid sizes).
pub fn lock_data(data: &[u8], password: &str) -> Vec<u8> {
    // 1. Generate random salt
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // 2. Derive 256-bit key from password+salt
    let mut key = [0u8; AES_GCM_256_KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITERS, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

    // 3. Random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 4. Encrypt (AES-GCM automatically provides authenticity tag)
    let ciphertext = cipher.encrypt(nonce, data).unwrap();

    // 5. Output = salt | nonce | ciphertext
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend(ciphertext);
    out
}

/// Decrypts protected data (`[salt | nonce | ciphertext+tag]`) with the password.
///
/// Returns `None` if the input is malformed, the password is wrong,
/// or authentication fails.
pub fn unlock_data(protected: &[u8], password: &str) -> Option<Vec<u8>> {
    if protected.len() < SALT_LEN + NONCE_LEN {
        return None; // Not enough bytes
    }

    // Split salt, nonce, and ciphertext
    let (salt, rest) = protected.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    // Derive key
    let mut key = [0u8; AES_GCM_256_KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERS, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

    // Try decrypting; return None on failure
    cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_unlock_round_trip() {
        let password = "correct horse battery staple";
        let data = b"Super secret data";

        let locked = lock_data(data, password);
        assert_ne!(locked, data, "locked data should differ from original");

        let unlocked = unlock_data(&locked, password).expect("should unlock");
        assert_eq!(unlocked, data, "unlocked data should match original");
    }

    #[test]
    fn wrong_password_fails() {
        let data = b"Another secret";
        let locked = lock_data(data, "goodpassword");

        let result = unlock_data(&locked, "badpassword");
        assert!(result.is_none(), "unlock with wrong password should fail");
    }

    #[test]
    fn empty_data_still_works() {
        let data: &[u8] = b"";
        let password = "mypassword";

        let locked = lock_data(data, password);
        let unlocked = unlock_data(&locked, password).expect("should unlock empty");
        assert_eq!(unlocked, data);
    }

    #[test]
    fn tampered_data_fails() {
        let password = "secret";
        let data = b"hello world";
        let mut locked = lock_data(data, password);

        // Flip a byte in the ciphertext
        locked[SALT_LEN + NONCE_LEN] ^= 0xFF;

        let result = unlock_data(&locked, password);
        assert!(result.is_none(), "tampered data must not decrypt");
    }
}
