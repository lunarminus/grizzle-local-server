//! The few cryptographic odds and ends the server needs, all from OpenSSL.

use openssl::hash::{hash, MessageDigest};

/// `count` bytes from the system's random number generator.
pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    openssl::rand::rand_bytes(&mut bytes).expect("the system's random number generator works");
    bytes
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Bytes from a hex string; `None` unless it is an even number of hex digits.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok()).collect()
}

/// `count` random bytes as hex.
pub fn random_hex(count: usize) -> String {
    hex(&random_bytes(count))
}

/// An unguessable token: `count` random bytes in URL-safe base64 without padding.
pub fn random_token(count: usize) -> String {
    openssl::base64::encode_block(&random_bytes(count))
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Constant-time comparison of two secrets. A missing or empty `given` matches nothing.
pub fn same_secret(given: Option<&str>, expected: &str) -> bool {
    let Some(given) = given.filter(|g| !g.is_empty()) else { return false };
    // Comparing digests keeps the time independent of where the two differ and of their lengths.
    let digest = |text: &str| hash(MessageDigest::sha256(), text.as_bytes()).expect("SHA-256 is available");
    openssl::memcmp::eq(&digest(given), &digest(expected))
}

/// PBKDF2-HMAC-SHA256 of `material`, as hex.
pub fn slow_hash(material: &[u8], salt: &[u8], rounds: u32) -> String {
    let mut out = [0u8; 32];
    openssl::pkcs5::pbkdf2_hmac(material, salt, rounds.max(1) as usize, MessageDigest::sha256(), &mut out)
        .expect("PBKDF2 with SHA-256 is available");
    hex(&out)
}

pub fn md5_hex(data: &[u8]) -> String {
    hex(&hash(MessageDigest::md5(), data).expect("MD5 is available"))
}

/// Standard base64, the lenient way HTTP clients' headers need: characters outside the alphabet
/// are skipped. `None` if what is left isn't whole (wrong padding).
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let clean: String = text.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')).collect();
    if clean.is_empty() {
        return Some(Vec::new());
    }
    if clean.len() % 4 != 0 {
        return None;
    }
    openssl::base64::decode_block(&clean).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_compare_whole() {
        assert!(same_secret(Some("pässword"), "pässword"));
        assert!(!same_secret(Some("password"), "pässword"));
        assert!(!same_secret(Some("pass"), "password"));
        assert!(!same_secret(Some(""), ""));
        assert!(!same_secret(None, ""));
        assert!(!same_secret(None, "x"));
    }

    #[test]
    fn tokens_are_url_safe_and_long() {
        let token = random_token(32);
        assert_eq!(token.len(), 43);
        assert!(token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(token, random_token(32));
        assert_eq!(random_hex(6).len(), 12);
    }

    #[test]
    fn known_digests() {
        assert_eq!(md5_hex(b"GRD-L0000TEST;isUnlocked=true").len(), 32);
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        // RFC 7914 section 11: PBKDF2-HMAC-SHA256("passwd", "salt", 1)
        assert_eq!(&slow_hash(b"passwd", b"salt", 1)[..32], "55ac046e56e3089fec1691c22544b605");
        assert_eq!(unhex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("0g"), None);
        assert_eq!(unhex("abc"), None);
    }

    #[test]
    fn base64_is_read_leniently() {
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(base64_decode("dXNlcjpw YXNz\n").unwrap(), b"user:pass");
        assert_eq!(base64_decode("dXNlcjo=").unwrap(), b"user:");
        assert_eq!(base64_decode("dXNlcjo"), None);
        assert_eq!(base64_decode("").unwrap(), b"");
    }
}
