//! Answers to the two password challenges: the classic VNC one, and the
//! user name and password a Mac's Screen Sharing asks for.

use aes::Aes128;
use des::cipher::{BlockCipherEncrypt, KeyInit};
use des::Des;
use md5::{Digest, Md5};
use num_bigint::BigUint;

use super::VncError;

/// VNC Authentication: the 16-byte challenge encrypted with DES, keyed by
/// the first eight bytes of the password with each byte's bits reversed.
/// Anything past eight bytes is ignored by every server.
pub(super) fn vnc_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (slot, byte) in key.iter_mut().zip(password.bytes()) {
        *slot = byte.reverse_bits();
    }
    let cipher = Des::new(&key.into());
    let mut response = *challenge;
    for block in response.as_chunks_mut::<8>().0 {
        cipher.encrypt_block(block.into());
    }
    response
}

/// Apple Remote Desktop sign-in. The server sends a Diffie-Hellman generator,
/// prime and public key. The reply is the user name and password, 64 bytes
/// each, under AES-128 keyed with the MD5 of the shared secret, then this
/// side's public key.
pub(super) fn apple_response(
    generator: &[u8],
    prime: &[u8],
    server_key: &[u8],
    username: &str,
    password: &str,
) -> Result<Vec<u8>, VncError> {
    let modulus = BigUint::from_bytes_be(prime);
    if modulus < BigUint::from(5u32) || server_key.len() != prime.len() {
        return Err(VncError::Protocol(
            "The Mac sent a key exchange this client cannot use.".to_string(),
        ));
    }
    let mut random = vec![0u8; prime.len()];
    rand::fill(&mut random[..]);
    // In 1 ..= p - 2, as a Diffie-Hellman secret must be.
    let secret =
        BigUint::from_bytes_be(&random) % (&modulus - BigUint::from(2u32)) + BigUint::from(1u32);
    let mut credentials = [0u8; 128];
    rand::fill(&mut credentials[..]);
    put_c_string(&mut credentials[..64], username);
    put_c_string(&mut credentials[64..], password);
    Ok(apple_reply(
        generator,
        &modulus,
        server_key,
        &secret,
        credentials,
    ))
}

fn apple_reply(
    generator: &[u8],
    modulus: &BigUint,
    server_key: &[u8],
    secret: &BigUint,
    mut credentials: [u8; 128],
) -> Vec<u8> {
    let width = server_key.len();
    let public = BigUint::from_bytes_be(generator).modpow(secret, modulus);
    let shared = BigUint::from_bytes_be(server_key).modpow(secret, modulus);
    let key = Md5::digest(fixed_width(&shared, width));
    let cipher = Aes128::new_from_slice(&key).expect("MD5 is 16 bytes");
    for block in credentials.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(block.into());
    }
    let mut reply = credentials.to_vec();
    reply.extend_from_slice(&fixed_width(&public, width));
    reply
}

/// Big-endian, padded on the left to the server's key length.
fn fixed_width(number: &BigUint, width: usize) -> Vec<u8> {
    let bytes = number.to_bytes_be();
    let skip = bytes.len().saturating_sub(width);
    let mut out = vec![0u8; width.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// At most 63 bytes and a NUL. The random bytes after it stay, as the
/// server expects.
fn put_c_string(field: &mut [u8], text: &str) {
    let length = text.len().min(field.len() - 1);
    field[..length].copy_from_slice(&text.as_bytes()[..length]);
    field[length] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn vnc_response_matches_des_with_reversed_key_bits() {
        let challenge: [u8; 16] = std::array::from_fn(|i| i as u8);
        let response = vnc_response("password", &challenge);
        // openssl enc -des-ecb -K 0e86ceceeef64e26 -nopad
        assert_eq!(response.to_vec(), hex("B866924125C8EEBB9DEBC1DB61C538E2"));
    }

    #[test]
    fn vnc_response_uses_only_eight_bytes_of_the_password() {
        let challenge = [7u8; 16];
        assert_eq!(
            vnc_response("password", &challenge),
            vnc_response("password-and-more", &challenge)
        );
        assert_ne!(
            vnc_response("passwore", &challenge),
            vnc_response("password", &challenge)
        );
    }

    #[test]
    fn apple_reply_encrypts_with_the_shared_secret() {
        // p = 23, g = 5. The server's secret is 6, so its key is 5^6 mod 23 = 8.
        // This side's secret is 15: its key is 5^15 mod 23 = 19 and the shared
        // secret is 8^15 mod 23 = 2.
        let mut credentials = [0u8; 128];
        put_c_string(&mut credentials[..64], "ada");
        put_c_string(&mut credentials[64..], "s3cret");
        let reply = apple_reply(
            &[5],
            &BigUint::from(23u32),
            &[8],
            &BigUint::from(15u32),
            credentials,
        );
        assert_eq!(reply.len(), 129);
        assert_eq!(reply[128], 19);
        // openssl enc -aes-128-ecb -nopad, keyed with MD5 of the byte 0x02.
        let expected = concat!(
            "ED384237CA5F62826BCF2544491308BDC9ACC9C2EEAB55BCDD7134A806D6C873",
            "C9ACC9C2EEAB55BCDD7134A806D6C873C9ACC9C2EEAB55BCDD7134A806D6C873",
            "3F906D45D5A9D81708E6B88660DA7BC9C9ACC9C2EEAB55BCDD7134A806D6C873",
            "C9ACC9C2EEAB55BCDD7134A806D6C873C9ACC9C2EEAB55BCDD7134A806D6C873"
        );
        assert_eq!(reply[..128].to_vec(), hex(expected));
    }

    #[test]
    fn apple_response_is_credentials_then_a_padded_public_key() {
        let prime = hex(concat!(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
        ));
        let server_key = {
            let mut key = vec![0u8; prime.len()];
            key[prime.len() - 1] = 2;
            key
        };
        let reply = apple_response(&[0, 2], &prime, &server_key, "ada", "s3cret").unwrap();
        assert_eq!(reply.len(), 128 + prime.len());
    }

    #[test]
    fn long_credentials_keep_their_terminator() {
        let mut field = [0xAAu8; 64];
        put_c_string(&mut field, &"x".repeat(100));
        assert!(field[..63].iter().all(|&b| b == b'x'));
        assert_eq!(field[63], 0);

        let mut field = [0xAAu8; 64];
        put_c_string(&mut field, "ada");
        assert_eq!(&field[..4], b"ada\0");
        assert_eq!(field[4], 0xAA);
    }

    #[test]
    fn fixed_width_pads_on_the_left() {
        assert_eq!(fixed_width(&BigUint::from(0x0102u32), 4), vec![0, 0, 1, 2]);
        assert_eq!(fixed_width(&BigUint::from(0u32), 2), vec![0, 0]);
    }
}
