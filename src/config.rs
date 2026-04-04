use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub backend: String,
    pub tick_rate_ms: u64,
    pub log_file: PathBuf,
    pub export_dir: PathBuf,
    pub auto_save: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            backend: "nftables".to_string(),
            tick_rate_ms: 250,
            log_file: PathBuf::from("/var/log/easyfirewall.log"),
            export_dir: PathBuf::from("~/.easyfirewall/exports"),
            auto_save: false,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        // Para v1.0, usar config por defecto
        // En versiones futuras, cargaremos desde archivos JSON/YAML
        Ok(Self::default())
    }

    #[allow(dead_code)]
    pub fn log_file(&self) -> &PathBuf {
        &self.log_file
    }

    #[allow(dead_code)]
    pub fn export_dir(&self) -> &PathBuf {
        &self.export_dir
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
        assert_eq!(config.export_dir, PathBuf::from("~/.easyfirewall/exports"));
        assert_eq!(config.auto_save, false);
    }

    #[test]
    fn test_load_config() {
        let config = Config::load().unwrap();
        assert_eq!(config.backend, "nftables");
    }
}
