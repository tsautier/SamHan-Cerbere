use md5::{Md5, Digest};

/// Verify CHAP (MD5). RFC 1994: Value = MD5( ChapID | PlainPassword | Challenge )
pub fn verify_chap(chap_id: u8, plain_password: &str, challenge: &[u8], value: &[u8;16]) -> bool {
    let mut hasher = Md5::new();
    hasher.update([chap_id]);
    hasher.update(plain_password.as_bytes());
    hasher.update(challenge);
    let out = hasher.finalize();
    &out[..16] == value
}
