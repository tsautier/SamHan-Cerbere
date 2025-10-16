use anyhow::Result;
use serde::{Serialize,Deserialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TotpSecret{ pub user:String, pub secret:Vec<u8>, pub digits:u32, pub period:u64 }

#[derive(Default)]
pub struct TotpStore{ pub path:String, pub entries:Vec<TotpSecret> }

impl TotpStore{
    pub fn load(path:&str)->Result<Self>{
        if !std::path::Path::new(path).exists(){ return Ok(Self{ path:path.to_string(), entries:vec![] }) }
        let txt=fs::read_to_string(path)?; let entries:Vec<TotpSecret>=serde_json::from_str(&txt)?;
        Ok(Self{ path:path.to_string(), entries })
    }
    pub fn save(&self)->Result<()>{ if let Some(dir)=std::path::Path::new(&self.path).parent(){ std::fs::create_dir_all(dir)?; } fs::write(&self.path, serde_json::to_string_pretty(&self.entries)?)?; Ok(()) }
    pub fn set(&mut self, rec:TotpSecret)->Result<()>{ self.entries.retain(|e| e.user!=rec.user); self.entries.push(rec); self.save() }
    pub fn get(&self, user:&str)->Option<TotpSecret>{ self.entries.iter().find(|e| e.user==user).cloned() }
    pub fn revoke(&mut self, user:&str)->Result<()>{ self.entries.retain(|e| e.user!=user); self.save() }
    pub fn list(&self)->&[TotpSecret]{ &self.entries }
}
