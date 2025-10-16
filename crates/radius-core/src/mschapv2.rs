// Minimal MSCHAPv2 verification helpers (RFC 2759).
// Requires user's NT hash (MD4 of Unicode password).

use md4::{Md4};
use sha1::{Sha1, Digest as _};
use des::cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray};
use des::Des;

pub fn nt_hash_from_password(password: &str) -> [u8;16] {
    use std::iter::FromIterator;
    // Password to UTF-16LE
    let mut le = Vec::with_capacity(password.len()*2);
    for ch in password.encode_utf16() {
        le.extend_from_slice(&ch.to_le_bytes());
    }
    let mut md4 = Md4::new();
    md4.update(&le);
    let out = md4.finalize();
    let mut h = [0u8;16];
    h.copy_from_slice(&out);
    h
}

// Derive DES keys from 56-bit segments of the 16-byte NT hash
fn des_key_from_7_bytes(input: &[u8]) -> [u8;8] {
    // Expand 7 bytes into 8 with parity bits (ignore correct parity for simplicity)
    let mut key = [0u8;8];
    key[0] = input[0] & 0xFE;
    key[1] = ((input[0] << 7) | (input[1] >> 1)) & 0xFE;
    key[2] = ((input[1] << 6) | (input[2] >> 2)) & 0xFE;
    key[3] = ((input[2] << 5) | (input[3] >> 3)) & 0xFE;
    key[4] = ((input[3] << 4) | (input[4] >> 4)) & 0xFE;
    key[5] = ((input[4] << 3) | (input[5] >> 5)) & 0xFE;
    key[6] = ((input[5] << 2) | (input[6] >> 6)) & 0xFE;
    key[7] =  (input[6] << 1) & 0xFE;
    key
}

fn des_encrypt(key7: &[u8], data8: &[u8;8]) -> [u8;8] {
    let key8 = des_key_from_7_bytes(key7);
    let cipher = Des::new_from_slice(&key8).unwrap();
    let mut block = GenericArray::clone_from_slice(data8);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8;8];
    out.copy_from_slice(&block);
    out
}

fn challenge_hash(peer_challenge: &[u8;16], auth_challenge: &[u8;16], username: &str) -> [u8;8] {
    let mut s = Sha1::new();
    s.update(peer_challenge);
    s.update(auth_challenge);
    s.update(username.as_bytes());
    let digest = s.finalize();
    let mut out=[0u8;8];
    out.copy_from_slice(&digest[..8]);
    out
}

pub fn nt_response(auth_challenge: &[u8;16], peer_challenge: &[u8;16], username: &str, nt_hash: &[u8;16]) -> [u8;24] {
    let chall = challenge_hash(peer_challenge, auth_challenge, username);
    // Split NT hash into three 7-byte keys (16 -> 21 with padding zeros)
    let mut z = [0u8;21];
    z[..16].copy_from_slice(nt_hash);
    let r1 = des_encrypt(&z[0..7], &chall);
    let r2 = des_encrypt(&z[7..14], &chall);
    let r3 = des_encrypt(&z[14..21], &chall);
    let mut resp = [0u8;24];
    resp[0..8].copy_from_slice(&r1);
    resp[8..16].copy_from_slice(&r2);
    resp[16..24].copy_from_slice(&r3);
    resp
}

pub fn verify_nt_response(expected: &[u8;24], auth_challenge: &[u8;16], peer_challenge: &[u8;16], username:&str, nt_hash:&[u8;16]) -> bool {
    let calc = nt_response(auth_challenge, peer_challenge, username, nt_hash);
    &calc == expected
}
