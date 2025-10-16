use crate::model::Rule;
use anyhow::Result;
use std::fs;

pub fn load_policies(dir:&str)->Result<Vec<Rule>>{
    let mut out=Vec::new();
    if let Ok(entries)=std::fs::read_dir(dir){
        for e in entries{
            if let Ok(ent)=e{
                let path=ent.path();
                if path.extension().and_then(|s|s.to_str())==Some("toml"){
                    let txt=fs::read_to_string(&path)?;
                    let v: toml::Value = toml::from_str(&txt)?;
                    if let Some(arr)=v.get("rules").and_then(|x|x.as_array()){
                        for r in arr{
                            let when=r.get("when").and_then(|x|x.as_str()).unwrap_or("").to_string();
                            let action=r.get("action").and_then(|x|x.as_str()).unwrap_or("allow_mfa").to_string();
                            out.push(Rule{when,action});
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}
