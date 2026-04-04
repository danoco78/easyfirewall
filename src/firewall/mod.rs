pub mod nftables;
pub mod iptables;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct FirewallRule {
    pub id: usize,
    pub action: String,
    pub protocol: String,
    pub port: Option<String>,
    pub source: String,
    pub destination: String,
    pub interface: Option<String>,
    pub origin: RuleOrigin,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleOrigin {
    System,
    EasyFirewall,
    External,
}

impl RuleOrigin {
    pub fn display_name(&self) -> &str {
        match self {
            RuleOrigin::System => "system",
            RuleOrigin::EasyFirewall => "easyfirewall",
            RuleOrigin::External => "external",
        }
    }
}

#[derive(Error, Debug)]
pub enum FirewallError {
    #[allow(dead_code)]
    #[error("Permission denied: root privileges required")]
    PermissionDenied,

    #[allow(dead_code)]
    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),

    #[error("Invalid rule: {0}")]
    InvalidRule(String),

    #[error("Failed to execute command: {0}")]
    CommandFailed(String),

    #[allow(dead_code)]
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, FirewallError>;

#[async_trait::async_trait]
pub trait FirewallBackend: Send + Sync {
    fn name(&self) -> &str;

    async fn list_rules(&self) -> Result<Vec<FirewallRule>>;

    async fn add_rule(&self, rule: &FirewallRule) -> Result<()>;

    async fn delete_rule(&self, rule_id: usize) -> Result<()>;

    async fn update_rule(&self, rule: &FirewallRule) -> Result<()>;

    async fn check_available(&self) -> Result<bool>;
}
