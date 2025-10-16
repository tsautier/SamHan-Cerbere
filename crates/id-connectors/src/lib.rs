pub mod file;
pub mod ldap;

pub trait IdentityBackend {
    fn authenticate(&self, user: &str, password: &str) -> bool;
}
