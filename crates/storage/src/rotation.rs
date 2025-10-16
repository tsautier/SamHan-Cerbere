use std::fs;
use chrono::Local;
pub fn rotate_if_needed(path:&str){
    if let Ok(meta)=fs::metadata(path){
        if meta.len()>1024*1024{
            let ts=Local::now().format("%Y%m%d%H%M%S").to_string();
            let new_path=format!("{}.{}", path, ts);
            let _=fs::rename(path, &new_path);
        }
    }
}
