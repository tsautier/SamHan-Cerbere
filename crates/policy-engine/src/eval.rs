use crate::model::{Rule, Decision};
use chrono::{Local, Timelike};

pub struct Context<'a>{ pub client_ip:&'a str, pub user: Option<&'a str> }

pub fn evaluate(rules:&[Rule], ctx:&Context)->Decision{
    let hour=Local::now().hour() as i32;
    for r in rules{
        let w=r.when.as_str();
        if w.contains("hour < 6") && hour<6 { return Decision::from_str(&r.action); }
        if w.contains("hour > 22") && hour>22 { return Decision::from_str(&r.action); }
        if w.contains("user ==") { if let Some(u)=ctx.user{ if w.contains(u){ return Decision::from_str(&r.action); } } }
        if w.contains("client_ip ==") && w.contains(ctx.client_ip){ return Decision::from_str(&r.action); }
    }
    Decision::AllowMfa
}
