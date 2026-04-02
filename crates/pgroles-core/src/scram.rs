//! SCRAM-SHA-256 verifier computation for PostgreSQL passwords.
//!
//! Computes verifier strings in the format PostgreSQL stores internally:
//!
//! ```text
//! SCRAM-SHA-256$<iterations>:<base64-salt>$<base64-StoredKey>:<base64-ServerKey>
//! ```
//!
//! When this string is passed via `ALTER ROLE ... PASSWORD`, PostgreSQL detects
//! the `SCRAM-SHA-256$` prefix and stores it directly — the cleartext password
//! never crosses the wire.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Default PBKDF2 iteration count, matching PostgreSQL's default.
pub const DEFAULT_ITERATIONS: u32 = 4096;

/// Compute a PostgreSQL SCRAM-SHA-256 verifier string.
///
/// The returned string can be passed directly to `ALTER ROLE ... PASSWORD` and
/// PostgreSQL will store it without re-hashing.
pub fn compute_verifier(password: &str, iterations: u32) -> String {
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);
    compute_verifier_with_salt(password, iterations, &salt)
}

/// Compute a verifier with an explicit salt (useful for testing).
fn compute_verifier_with_salt(password: &str, iterations: u32, salt: &[u8]) -> String {
    // 1. Derive salted password via PBKDF2-HMAC-SHA256.
    let mut salted_password = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut salted_password);

    // 2. ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")
    let mut client_key = hmac_sha256(&salted_password, b"Client Key");

    // 3. StoredKey = SHA256(ClientKey)
    let stored_key = Sha256::digest(&client_key);

    // 4. ServerKey = HMAC-SHA256(SaltedPassword, "Server Key")
    let mut server_key = hmac_sha256(&salted_password, b"Server Key");

    // 5. Format as PostgreSQL SCRAM-SHA-256 verifier string.
    let verifier = format!(
        "SCRAM-SHA-256${iterations}:{salt}${stored_key}:{server_key}",
        salt = BASE64.encode(salt),
        stored_key = BASE64.encode(stored_key),
        server_key = BASE64.encode(&server_key),
    );

    // 6. Zeroize sensitive intermediate key material.
    salted_password.zeroize();
    client_key.zeroize();
    server_key.zeroize();

    verifier
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_has_correct_prefix() {
        let verifier = compute_verifier("hunter2", DEFAULT_ITERATIONS);
        assert!(
            verifier.starts_with("SCRAM-SHA-256$"),
            "verifier should start with SCRAM-SHA-256$, got: {verifier}"
        );
    }

    #[test]
    fn verifier_has_correct_structure() {
        let verifier = compute_verifier("test-password", DEFAULT_ITERATIONS);
        // Format: SCRAM-SHA-256$<iter>:<b64-salt>$<b64-StoredKey>:<b64-ServerKey>
        let rest = verifier.strip_prefix("SCRAM-SHA-256$").unwrap();
        let (iter_salt, keys) = rest.split_once('$').expect("should have $ separator");
        let (iter_str, salt_b64) = iter_salt
            .split_once(':')
            .expect("should have : in iter:salt");
        let (stored_key_b64, server_key_b64) = keys.split_once(':').expect("should have : in keys");

        assert_eq!(iter_str, "4096");

        let salt = BASE64
            .decode(salt_b64)
            .expect("salt should be valid base64");
        assert_eq!(salt.len(), 16, "salt should be 16 bytes");

        let stored_key = BASE64
            .decode(stored_key_b64)
            .expect("StoredKey should be valid base64");
        assert_eq!(
            stored_key.len(),
            32,
            "StoredKey should be 32 bytes (SHA-256)"
        );

        let server_key = BASE64
            .decode(server_key_b64)
            .expect("ServerKey should be valid base64");
        assert_eq!(
            server_key.len(),
            32,
            "ServerKey should be 32 bytes (SHA-256)"
        );
    }

    #[test]
    fn different_passwords_produce_different_verifiers() {
        let salt = [1u8; 16];
        let v1 = compute_verifier_with_salt("password-a", DEFAULT_ITERATIONS, &salt);
        let v2 = compute_verifier_with_salt("password-b", DEFAULT_ITERATIONS, &salt);
        assert_ne!(v1, v2);
    }

    #[test]
    fn same_password_different_salt_produces_different_verifiers() {
        let v1 = compute_verifier_with_salt("same-password", DEFAULT_ITERATIONS, &[1u8; 16]);
        let v2 = compute_verifier_with_salt("same-password", DEFAULT_ITERATIONS, &[2u8; 16]);
        assert_ne!(v1, v2);
    }

    #[test]
    fn deterministic_with_fixed_salt() {
        let v1 = compute_verifier_with_salt("deterministic", 4096, &[42u8; 16]);
        let v2 = compute_verifier_with_salt("deterministic", 4096, &[42u8; 16]);
        assert_eq!(v1, v2);
    }

    #[test]
    fn known_vector_matches_rfc7677() {
        // Test vector from RFC 7677 Appendix B (SCRAM-SHA-256):
        // username = "user", password = "pencil", iterations = 4096,
        // salt = W22ZaJ0SNY7soEsUEjb6gQ== (base64)
        //
        // Expected StoredKey and ServerKey from the RFC:
        //   StoredKey = WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=
        //   ServerKey = wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=
        let salt = BASE64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let verifier = compute_verifier_with_salt("pencil", 4096, &salt);
        assert_eq!(
            verifier,
            "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==\
             $WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=\
             :wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
        );
    }
}
