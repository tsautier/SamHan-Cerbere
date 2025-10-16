//! storage — skeleton

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub ts: u64,
    pub user: String,
    pub action: String,
    pub ok: bool,
}
