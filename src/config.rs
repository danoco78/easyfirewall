use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub backend: String,
    pub tick_rate_ms: u64,
    pub log_file: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            backend: "nftables".to_string(),
            tick_rate_ms: 250,
            log_file: PathBuf::from("/var/log/easyfirewall.log"),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        // Para v0.1, usamos config por defecto
        // En versiones futuras, cargaremos desde archivos JSON/YAML
        Ok(Self::default())
    }

    pub fn log_file(&self) -> &PathBuf {
        &self.log_file
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.backend, "nftables");
        assert_eq!(config.tick_rate_ms, 250);
        assert_eq!(config.log_file, PathBuf::from("/var/log/easyfirewall.log"));
    }

    #[test]
    fn test_load_config() {
        let config = Config::load().unwrap();
        assert_eq!(config.backend, "nftables");
    }
}
