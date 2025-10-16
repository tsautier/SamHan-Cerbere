use tracing_subscriber::{fmt, EnvFilter};

pub fn init(){
    let json=std::env::var("CERBERE_LOG_JSON").ok().as_deref()==Some("1");
    let filter=EnvFilter::from_default_env();
    if json{ let _=fmt().with_env_filter(filter).json().try_init(); }
    else { let _=fmt().with_env_filter(filter).try_init(); }
}
