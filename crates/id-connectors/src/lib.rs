//! id-connectors — skeleton

pub trait IdentityBackend {
    fn authenticate(&self, user: &str, password: &str) -> bool;
}

pub struct FileBackend;

impl IdentityBackend for FileBackend {
    fn authenticate(&self, _user: &str, _password: &str) -> bool { true }
}
