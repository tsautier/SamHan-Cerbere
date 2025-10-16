use md5::Context;

/// Verify CHAP (MD5). RFC 1994: Value = MD5( ChapID | PlainPassword | Challenge )
pub fn verify_chap(chap_id: u8, plain_password: &str, challenge: &[u8], value: &[u8;16]) -> bool {
    let mut hasher = Context::new();
    hasher.consume([chap_id]);
    hasher.consume(plain_password.as_bytes());
    hasher.consume(challenge);
    let out = hasher.compute();
    &out[..16] == value
}
