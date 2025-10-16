use md5::{Md5, Digest};

/// Decrypt PAP User-Password per RFC2865 using shared secret and request authenticator.
pub fn decrypt_user_password(enc: &[u8], shared_secret: &str, request_authenticator: &[u8;16]) -> Option<Vec<u8>> {
    if enc.is_empty() || enc.len() % 16 != 0 { return None; }
    let mut res = Vec::with_capacity(enc.len());
    let mut b = [0u8;16];
    let mut prev = request_authenticator.to_vec();

    for chunk in enc.chunks(16) {
        let mut hasher = Md5::new();
        hasher.update(shared_secret.as_bytes());
        hasher.update(&prev);
        let c = hasher.finalize();
        for i in 0..16 { b[i] = chunk[i] ^ c[i]; }
        res.extend_from_slice(&b);
        prev = chunk.to_vec();
    }
    // strip trailing nulls
    while let Some(&0) = res.last() { res.pop(); }
    Some(res)
}
