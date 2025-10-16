pub fn redact(s:&str)->String{ if s.len()<=2{ return "**".into() } format!("{}***{}", &s[..1], &s[s.len()-1..]) }
