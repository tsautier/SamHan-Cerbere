use base32::{Alphabet, encode};
use rand::RngCore;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Totp { pub secret: Vec<u8>, pub digits: u32, pub period: u64 }

impl Totp{
    pub fn new(secret:Vec<u8>, digits:u32, period:u64)->Self{ Self{secret,digits,period} }
    pub fn generate_uri(&self, user:&str, issuer:&str)->String{
        let secret_b32=encode(Alphabet::RFC4648{padding:false}, &self.secret);
        format!("otpauth://totp/{issuer}:{user}?secret={secret}&issuer={issuer}&period={period}&digits={digits}",
            issuer=issuer,user=user,secret=secret_b32,period=self.period,digits=self.digits)
    }
    pub fn verify(&self, code:&str, skew:i64)->bool{
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let step=(now / self.period as i64) as i64;
        for i in -skew..=skew{ if self.generate_code_for(step+i)==code{ return true; } }
        false
    }
    fn generate_code_for(&self, step:i64)->String{
        type HmacSha1=Hmac<Sha1>;
        let mut mac=HmacSha1::new_from_slice(&self.secret).unwrap();
        let msg=(step as i64).to_be_bytes(); mac.update(&msg);
        let res=mac.finalize().into_bytes();
        let offset=(res[19] & 0x0f) as usize;
        let bin=((u32::from(res[offset]) & 0x7f)<<24)|((u32::from(res[offset+1])&0xff)<<16)|((u32::from(res[offset+2])&0xff)<<8)|(u32::from(res[offset+3])&0xff);
        let code=bin % 10u32.pow(self.digits); format!("{:0width$}", code, width=self.digits as usize)
    }
}
pub fn random_secret(len:usize)->Vec<u8>{ let mut b=vec![0u8;len]; rand::thread_rng().fill_bytes(&mut b); b }
