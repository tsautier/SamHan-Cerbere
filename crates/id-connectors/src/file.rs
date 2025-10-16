use serde::{Serialize, Deserialize};
use std::fs;
use anyhow::Result;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use password_hash::SaltString;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserRecord { pub username:String, pub hash:String }

#[derive(Default)]
pub struct FileBackend { pub path:String, pub users:Vec<UserRecord> }

impl FileBackend {
    pub fn load(path:&str)->Result<Self>{
        if !std::path::Path::new(path).exists(){ return Ok(Self{ path:path.to_string(), users:vec![] }) }
        let txt=fs::read_to_string(path)?;
        let users:Vec<UserRecord>=serde_json::from_str(&txt)?;
        Ok(Self{ path:path.to_string(), users })
    }
    pub fn save(&self)->Result<()>{
        if let Some(dir)=std::path::Path::new(&self.path).parent(){ std::fs::create_dir_all(dir)?; }
        fs::write(&self.path, serde_json::to_string_pretty(&self.users)?)?; Ok(())
    }
    pub fn add_user(&mut self, username:&str, password:&str)->Result<()>{
        let salt=SaltString::generate(&mut rand::thread_rng());
        let hash=argon2::Argon2::default().hash_password(password.as_bytes(), &salt)?.to_string();
        self.users.push(UserRecord{ username:username.to_string(), hash });
        self.save()
    }
    pub fn list(&self)->&[UserRecord]{ &self.users }
    pub fn authenticate(&self, user:&str, pass:&str)->bool{
        if let Some(u)=self.users.iter().find(|u| u.username==user){
            if let Ok(parsed)=PasswordHash::new(&u.hash){
                return Argon2::default().verify_password(pass.as_bytes(), &parsed).is_ok();
            }
        }
        false
    }
}
