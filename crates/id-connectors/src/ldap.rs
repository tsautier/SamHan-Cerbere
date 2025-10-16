pub struct LdapBackend {
    pub url:String, pub bind_dn:String, pub bind_password:String, pub user_base_dn:String
}
impl LdapBackend {
    pub fn new(url:String, bind_dn:String, bind_password:String, user_base_dn:String)->Self{ Self{url,bind_dn,bind_password,user_base_dn} }
    pub fn authenticate(&self, _user:&str, _password:&str)->bool{ true } // stub
}
