use anyhow::{bail, Result};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code { AccessRequest=1, AccessAccept=2, AccessReject=3, AccessChallenge=11 }

impl Code { pub fn from_u8(v:u8)->Option<Self>{ match v{1=>Some(Self::AccessRequest),2=>Some(Self::AccessAccept),3=>Some(Self::AccessReject),11=>Some(Self::AccessChallenge),_=>None}}}

#[derive(Debug, Clone)]
pub struct Header { pub code: Code, pub identifier: u8, pub length: u16, pub authenticator: [u8;16] }

impl Header {
    pub const LEN: usize = 20;
    pub fn parse(buf:&[u8])->Result<(Self,&[u8])>{
        if buf.len()<Self::LEN{bail!("radius header too short")}
        let code=Code::from_u8(buf[0]).ok_or_else(||anyhow::anyhow!("unsupported code"))?;
        let identifier=buf[1]; let length=u16::from_be_bytes([buf[2],buf[3]]);
        if length as usize>buf.len(){bail!("declared length larger than buffer")}
        let mut authenticator=[0u8;16]; authenticator.copy_from_slice(&buf[4..20]);
        let rest=&buf[20..length as usize];
        Ok((Self{code,identifier,length,authenticator},rest))
    }
    pub fn encode(&self,out:&mut Vec<u8>){ out.push(self.code as u8); out.push(self.identifier); out.extend_from_slice(&self.length.to_be_bytes()); out.extend_from_slice(&self.authenticator); }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr{ State(Vec<u8>), ChapPassword{ id:u8, hash:[u8;16] }, ChapChallenge(Vec<u8>), EapMessage(Vec<u8>),  UserName(String), UserPassword(Vec<u8>), VendorSpecific(u32,Vec<u8>), Other(u8,Vec<u8>) }

pub fn parse_attrs(mut buf:&[u8])->Result<Vec<Attr>>{
    let mut out=Vec::new();
    while !buf.is_empty(){
        if buf.len()<2{break}
        let t=buf[0]; let l=buf[1] as usize; if l<2||l>buf.len(){break}
        let v=&buf[2..l];
        match t{
            1=>out.push(Attr::UserName(String::from_utf8_lossy(v).into_owned())),
            2=>out.push(Attr::UserPassword(v.to_vec())),
            26=>{ if v.len()>=4{ let vid=u32::from_be_bytes([v[0],v[1],v[2],v[3]]); out.push(Attr::VendorSpecific(vid, v[4..].to_vec())); } else { out.push(Attr::Other(t,v.to_vec())) } }
            24=>out.push(Attr::State(v.to_vec())),
            3=>{ if v.len()==17 { let mut h=[0u8;16]; h.copy_from_slice(&v[1..]); out.push(Attr::ChapPassword{ id:v[0], hash:h }); } },
            60=>out.push(Attr::ChapChallenge(v.to_vec())),
            79=>out.push(Attr::EapMessage(v.to_vec())),
            _=>out.push(Attr::Other(t,v.to_vec())),
        }
        buf=&buf[l..];
    }
    Ok(out)
}

pub fn encode_attrs(attrs:&[Attr], out:&mut Vec<u8>){
    for a in attrs{
        match a{
            Attr::UserName(s)=>{ let v=s.as_bytes(); out.push(1); out.push((v.len()+2) as u8); out.extend_from_slice(v); }
            Attr::UserPassword(b)=>{ out.push(2); out.push((b.len()+2) as u8); out.extend_from_slice(b); }
            Attr::VendorSpecific(vid,data)=>{ out.push(26); out.push((data.len()+6) as u8); out.extend_from_slice(&vid.to_be_bytes()); out.extend_from_slice(data); }
            Attr::Other(t,data)=>{ out.push(*t); out.push((data.len()+2) as u8); out.extend_from_slice(data); }
            Attr::State(data)=>{ out.push(24); out.push((data.len()+2) as u8); out.extend_from_slice(data); }
            Attr::ChapPassword{ id, hash }=>{ out.push(3); out.push(19); out.push(*id); out.extend_from_slice(hash); }
            Attr::ChapChallenge(data)=>{ out.push(60); out.push((data.len()+2) as u8); out.extend_from_slice(data); }
            Attr::EapMessage(data)=>{ out.push(79); out.push((data.len()+2) as u8); out.extend_from_slice(data); }
        }
    }
}
