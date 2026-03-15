use crate::firewall::FirewallRule;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedRule {
    pub id: usize,
    pub action: String,
    pub protocol: String,
    pub port: Option<String>,
    pub source: String,
    pub destination: String,
    pub interface: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
}

impl From<FirewallRule> for ExportedRule {
    fn from(rule: FirewallRule) -> Self {
        Self {
            id: rule.id,
            action: rule.action,
            protocol: rule.protocol,
            port: rule.port,
            source: rule.source,
            destination: rule.destination,
            interface: rule.interface,
            description: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedConfig {
    pub version: String,
    pub backend: String,
    pub rules: Vec<ExportedRule>,
    pub exported_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Yaml,
}

impl ExportFormat {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "json" => Some(ExportFormat::Json),
            "yaml" | "yml" => Some(ExportFormat::Yaml),
            _ => None,
        }
    }
}

pub struct RuleExporter;

impl RuleExporter {
    pub async fn export_rules(
        rules: &[FirewallRule],
        backend: &str,
        path: &PathBuf,
    ) -> std::io::Result<()> {
        let format = ExportFormat::from_extension(
            path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("json"),
        )
        .unwrap_or(ExportFormat::Json);

        let config = ExportedConfig {
            version: "1.0.0".to_string(),
            backend: backend.to_string(),
            rules: rules.iter().map(|r| r.clone().into()).collect(),
            exported_at: chrono::Utc::now().to_rfc3339(),
        };

        let content = match format {
            ExportFormat::Json => {
                serde_json::to_string_pretty(&config).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })?
            }
            ExportFormat::Yaml => {
                serde_yaml::to_string(&config).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })?
            }
        };

        // Crear directorio padre si no existe
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Escribir archivo
        fs::write(path, content).await?;

        Ok(())
    }

    pub async fn import_rules(
        path: &PathBuf,
    ) -> std::io::Result<Vec<ExportedRule>> {
        let content = fs::read_to_string(path).await?;

        let format = ExportFormat::from_extension(
            path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("json"),
        )
        .unwrap_or(ExportFormat::Json);

        let config: ExportedConfig = match format {
            ExportFormat::Json => {
                serde_json::from_str(&content).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                })?
            }
            ExportFormat::Yaml => {
                serde_yaml::from_str(&content).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                })?
            }
        };

        Ok(config.rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exported_rule_from_firewall_rule() {
        let firewall_rule = FirewallRule {
            id: 1,
            action: "ACCEPT".to_string(),
            protocol: "tcp".to_string(),
            port: Some("22".to_string()),
            source: "0.0.0.0/0".to_string(),
            destination: "0.0.0.0/0".to_string(),
            interface: Some("eth0".to_string()),
            packets: 100,
            bytes: 1000,
        };

        let exported = ExportedRule::from(firewall_rule);

        assert_eq!(exported.id, 1);
        assert_eq!(exported.action, "ACCEPT");
        assert_eq!(exported.protocol, "tcp");
        assert_eq!(exported.port, Some("22".to_string()));
        assert_eq!(exported.interface, Some("eth0".to_string()));
    }

    #[test]
    fn test_export_format_from_extension() {
        assert_eq!(
            ExportFormat::from_extension("json"),
            Some(ExportFormat::Json)
        );
        assert_eq!(
            ExportFormat::from_extension("yaml"),
            Some(ExportFormat::Yaml)
        );
        assert_eq!(
            ExportFormat::from_extension("yml"),
            Some(ExportFormat::Yaml)
        );
        assert_eq!(ExportFormat::from_extension("txt"), None);
    }

    #[tokio::test]
    async fn test_export_import_json() {
        use tempfile::NamedTempFile;

        let rules = vec![FirewallRule {
            id: 1,
            action: "ACCEPT".to_string(),
            protocol: "tcp".to_string(),
            port: Some("22".to_string()),
            source: "0.0.0.0/0".to_string(),
            destination: "0.0.0.0/0".to_string(),
            interface: None,
            packets: 0,
            bytes: 0,
        }];

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.into_temp_path();
        let path_buf = path.to_path_buf();

        // Exportar
        RuleExporter::export_rules(&rules, "nftables", &path_buf)
            .await
            .unwrap();

        // Verificar que el archivo existe
        assert!(path.exists());

        // Importar
        let imported = RuleExporter::import_rules(&path_buf).await.unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].id, 1);
        assert_eq!(imported[0].action, "ACCEPT");
    }

    #[tokio::test]
    async fn test_export_import_yaml() {
        use tempfile::NamedTempFile;

        let rules = vec![FirewallRule {
            id: 1,
            action: "DROP".to_string(),
            protocol: "udp".to_string(),
            port: Some("53".to_string()),
            source: "0.0.0.0/0".to_string(),
            destination: "0.0.0.0/0".to_string(),
            interface: None,
            packets: 0,
            bytes: 0,
        }];

        let mut temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.into_temp_path().with_extension("yaml");
        let path_buf = path.to_path_buf();

        // Exportar
        RuleExporter::export_rules(&rules, "nftables", &path_buf)
            .await
            .unwrap();

        // Verificar que el archivo existe
        assert!(path.exists());

        // Importar
        let imported = RuleExporter::import_rules(&path_buf).await.unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].id, 1);
        assert_eq!(imported[0].action, "DROP");
    }
}
