use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimit {
    pub per_min_user: u32,
    pub per_min_ip: u32,
    users: HashMap<String,(u32,Instant)>,
    ips: HashMap<String,(u32,Instant)>,
    lockouts: HashMap<String,Instant>,
    pub lockout_after: u32,
    pub lockout_duration: Duration,
}
impl Default for RateLimit {
    fn default()->Self{ Self{ per_min_user:60, per_min_ip:120, users:HashMap::new(), ips:HashMap::new(), lockouts:HashMap::new(), lockout_after:5, lockout_duration:Duration::from_secs(900)} }
}
impl RateLimit {
    pub fn allowed(&mut self, user:&str, ip:&str)->bool{
        let now=Instant::now();
        if let Some(until)=self.lockouts.get(user){ if *until>now { return false; } }
        let e=self.users.entry(user.to_string()).or_insert((0,now)); if now.duration_since(e.1)>Duration::from_secs(60){ *e=(0,now);} e.0+=1; if e.0>self.per_min_user{ return false; }
        let e2=self.ips.entry(ip.to_string()).or_insert((0,now)); if now.duration_since(e2.1)>Duration::from_secs(60){ *e2=(0,now);} e2.0+=1; if e2.0>self.per_min_ip{ return false; }
        true
    }
    pub fn record_failure(&mut self, user:&str){ let now=Instant::now(); let e=self.users.entry(user.to_string()).or_insert((0,now)); if e.0>=self.lockout_after { self.lockouts.insert(user.to_string(), now+self.lockout_duration); } }
}
