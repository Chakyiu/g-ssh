use std::fmt;

use bip39::Mnemonic;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::vault::error::VaultError;

/// 24-word BIP39 phrase. Its 32 entropy bytes are used directly as the KEK for
/// `enc_dek_by_recovery`. Display and Debug are masked.
pub struct RecoveryPhrase(SecretString);

impl RecoveryPhrase {
    /// Also returns the entropy, which is the KEK for `enc_dek_by_recovery`.
    pub(crate) fn generate() -> (Self, Zeroizing<[u8; 32]>) {
        let mut entropy = Zeroizing::new([0u8; 32]);
        super::crypto::fill_random(&mut entropy[..]);

        let mnemonic = Mnemonic::from_entropy(&entropy[..])
            .expect("32-byte entropy always yields a valid 24-word mnemonic");

        let phrase = Self(SecretString::from(mnemonic.to_string()));
        (phrase, entropy)
    }

    /// Only 24-word phrases are accepted.
    pub fn from_words(s: &str) -> Result<Self, VaultError> {
        let word_count = s.split_whitespace().count();
        if word_count != 24 {
            return Err(VaultError::InvalidRecoveryPhrase);
        }

        Mnemonic::parse_normalized(s)
            .map_err(|_| VaultError::InvalidRecoveryPhrase)
            .map(|m| Self(SecretString::from(m.to_string())))
    }

    /// The entropy, which is the recovery KEK.
    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mnemonic = Mnemonic::parse_normalized(self.0.expose_secret())
            .expect("stored phrase was validated at construction time");

        let entropy = Zeroizing::new(mnemonic.to_entropy());
        debug_assert_eq!(
            entropy.len(),
            32,
            "24-word mnemonic must encode exactly 32 bytes"
        );

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&entropy);
        Zeroizing::new(bytes)
    }

    /// Call only to show the phrase to the user.
    pub fn expose_words(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[recovery phrase]")
    }
}

impl fmt::Display for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[recovery phrase]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_decode_roundtrip() {
        let (phrase, entropy) = RecoveryPhrase::generate();
        let decoded = phrase.to_bytes();
        assert_eq!(*entropy, *decoded);
    }

    #[test]
    fn parse_and_decode_roundtrip() {
        let (phrase, entropy) = RecoveryPhrase::generate();
        let words = phrase.expose_words().to_string();

        let reparsed = RecoveryPhrase::from_words(&words).unwrap();
        assert_eq!(*entropy, *reparsed.to_bytes());
    }

    #[test]
    fn rejects_12_words() {
        let twelve = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        assert!(matches!(
            RecoveryPhrase::from_words(twelve),
            Err(VaultError::InvalidRecoveryPhrase)
        ));
    }

    #[test]
    fn rejects_23_words() {
        let (phrase, _) = RecoveryPhrase::generate();
        let words: Vec<&str> = phrase.expose_words().split_whitespace().collect();
        let twenty_three = words[..23].join(" ");
        assert!(matches!(
            RecoveryPhrase::from_words(&twenty_three),
            Err(VaultError::InvalidRecoveryPhrase)
        ));
    }

    #[test]
    fn rejects_invalid_words() {
        let garbage = vec!["notaword"; 24].join(" ");
        assert!(matches!(
            RecoveryPhrase::from_words(&garbage),
            Err(VaultError::InvalidRecoveryPhrase)
        ));
    }

    #[test]
    fn rejects_valid_12word_checksum_as_24() {
        let twelve = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        assert!(matches!(
            RecoveryPhrase::from_words(twelve),
            Err(VaultError::InvalidRecoveryPhrase)
        ));
    }

    #[test]
    fn debug_is_masked() {
        let (phrase, _) = RecoveryPhrase::generate();
        assert_eq!(format!("{phrase:?}"), "[recovery phrase]");
    }

    #[test]
    fn display_is_masked() {
        let (phrase, _) = RecoveryPhrase::generate();
        assert_eq!(format!("{phrase}"), "[recovery phrase]");
    }

    #[test]
    fn two_generated_phrases_are_distinct() {
        let (p1, e1) = RecoveryPhrase::generate();
        let (p2, e2) = RecoveryPhrase::generate();
        assert_ne!(*e1, *e2);
        assert_ne!(p1.expose_words(), p2.expose_words());
    }
}
