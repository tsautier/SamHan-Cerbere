use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerCfg { pub bind:String, pub shared_secret:String, #[serde(default="default_concurrency")] pub concurrency:u32, #[serde(default)] pub hot_reload:bool }
fn default_concurrency()->u32{1024}

#[derive(Debug, Deserialize, Clone)]
pub struct BackendPrimary{ pub r#type:String, #[serde(default)] pub url:Option<String>, #[serde(default)] pub bind_dn:Option<String>, #[serde(default)] pub bind_password:Option<String>, #[serde(default)] pub user_base_dn:Option<String>, #[serde(default)] pub group_base_dn:Option<String> }
#[derive(Debug, Deserialize, Clone)]
pub struct BackendCfg{ pub primary: BackendPrimary }

#[derive(Debug, Deserialize, Clone)]
pub struct CerbereConfig{ pub server:ServerCfg, pub backend:BackendCfg }

#[derive(thiserror::Error, Debug)]
pub enum ConfigError{
    #[error("toml parse error: {0}")] Toml(#[from] toml::de::Error),
    #[error("io error: {0}")] Io(#[from] std::io::Error),
    #[error("validation error: {0}")] Validation(String),
}

pub fn load_config(path:&str)->Result<CerbereConfig, ConfigError>{
    let txt=std::fs::read_to_string(path)?;
    let mut cfg: CerbereConfig = toml::from_str(&txt)?;
    resolve_env(&mut cfg);
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg:&CerbereConfig)->Result<(), ConfigError>{
    if cfg.server.bind.trim().is_empty(){ return Err(ConfigError::Validation("server.bind must not be empty".into())) }
    if cfg.server.shared_secret.trim().is_empty(){ return Err(ConfigError::Validation("server.shared_secret must not be empty".into())) }
    if cfg.backend.primary.r#type.trim().is_empty(){ return Err(ConfigError::Validation("backend.primary.type must not be empty".into())) }
    Ok(())
}

fn resolve_env(cfg:&mut CerbereConfig){
    if let Some(rest)=cfg.server.shared_secret.strip_prefix("env:"){ if let Ok(v)=std::env::var(rest){ cfg.server.shared_secret=v; } }
    if let Some(bp)=cfg.backend.primary.bind_password.as_mut(){
        if let Some(rest)=bp.strip_prefix("env:"){ if let Ok(v)=std::env::var(rest){ *bp=v; } }
    }
}
