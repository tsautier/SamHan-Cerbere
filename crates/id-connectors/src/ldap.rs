use ldap3::{LdapConn, Scope, SearchEntry};
use ldap3::result::Result as LdapResult;

pub fn auth_simple(url:&str, bind_dn:&str, bind_password:&str, user_base_dn:&str, user:&str, password:&str) -> LdapResult<bool> {
    let mut ldap = LdapConn::new(url)?;
    ldap.simple_bind(bind_dn, bind_password)?.success()?;
    // Heuristic filter: try sAMAccountName or uid
    let filter = format!("(|(sAMAccountName={})(uid={}))", user, user);
    let (rs, _res) = ldap.search(user_base_dn, Scope::Subtree, &filter, vec!["dn"])?.success()?;
    if rs.is_empty() { return Ok(false); }
    let entry = SearchEntry::construct(rs[0].clone());
    let user_dn = entry.dn;
    let ok = ldap.simple_bind(&user_dn, password)?.success().is_ok();
    // Re-bind as service to keep connection consistent
    let _ = ldap.simple_bind(bind_dn, bind_password)?.success();
    Ok(ok)
}
