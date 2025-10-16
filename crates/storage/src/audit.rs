use std::fs::{self, OpenOptions};
use std::io::Write;

#[derive(Debug, Clone)]
pub struct AuditRecord{ pub ts:u64, pub user:String, pub client_ip:String, pub action:String, pub result:String }

pub struct Audit{ pub path:String }

impl Audit{
    pub fn new(path:&str)->Self{ Self{ path:path.to_string() } }
    pub fn append(&self, rec:&AuditRecord)->std::io::Result<()>{
        if let Some(dir)=std::path::Path::new(&self.path).parent(){ fs::create_dir_all(dir)?; }
        let mut f=OpenOptions::new().create(true).append(true).open(&self.path)?;
        let line=format!("{},{},{},{},{}\n", rec.ts, rec.user, rec.client_ip, rec.action, rec.result);
        f.write_all(line.as_bytes())
    }
}
