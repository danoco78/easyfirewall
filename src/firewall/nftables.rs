use super::{FirewallBackend, FirewallError, FirewallRule, Result};
use tokio::process::Command;

pub struct NftablesBackend;

impl NftablesBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl FirewallBackend for NftablesBackend {
    fn name(&self) -> &str {
        "nftables"
    }

    async fn check_available(&self) -> Result<bool> {
        let output = Command::new("which")
            .arg("nft")
            .output()
            .await?;

        Ok(output.status.success())
    }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        let output = Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .await
            .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(stderr.to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_ruleset(&stdout)
    }
}

impl NftablesBackend {
    fn parse_ruleset(&self, ruleset: &str) -> Result<Vec<FirewallRule>> {
        let mut rules = Vec::new();
        let mut rule_id = 1;

        // Parseo básico de nftables output
        // Este es un parser simple para la v0.1, se mejorará en versiones posteriores
        for line in ruleset.lines() {
            let line = line.trim();

            // Ignorar líneas de configuración (table, chain, etc.)
            if line.is_empty()
                || line.starts_with("table")
                || line.starts_with("chain")
                || line.starts_with("#")
                || line.starts_with("}")
                || line.starts_with("{")
            {
                continue;
            }

            // Parsear regla tipo: "meta l4proto tcp tcp dport 22 accept"
            if let Some(rule) = self.parse_rule_line(line, rule_id) {
                rules.push(rule);
                rule_id += 1;
            }
        }

        Ok(rules)
    }

    fn parse_rule_line(&self, line: &str, id: usize) -> Option<FirewallRule> {
        // Simplificado para v0.1: buscar patrones comunes
        let line_lower = line.to_lowercase();

        // Determinar acción
        let action = if line_lower.contains("accept") {
            "ACCEPT".to_string()
        } else if line_lower.contains("drop") {
            "DROP".to_string()
        } else if line_lower.contains("reject") {
            "REJECT".to_string()
        } else {
            "UNKNOWN".to_string()
        };

        // Determinar protocolo
        let protocol = if line_lower.contains("tcp") {
            "tcp".to_string()
        } else if line_lower.contains("udp") {
            "udp".to_string()
        } else if line_lower.contains("icmp") {
            "icmp".to_string()
        } else {
            "all".to_string()
        };

        // Extraer puerto (básico)
        let port = if line_lower.contains("dport") {
            // Buscar número después de "dport"
            self.extract_after_keyword(line, "dport")
                .or_else(|| self.extract_after_keyword(line, "port"))
        } else {
            None
        };

        // Origen y destino (default para v0.1)
        let source = "0.0.0.0/0".to_string();
        let destination = "0.0.0.0/0".to_string();

        Some(FirewallRule {
            id,
            action,
            protocol,
            port,
            source,
            destination,
            interface: None,
            packets: 0,
            bytes: 0,
        })
    }

    fn extract_after_keyword(&self, line: &str, keyword: &str) -> Option<String> {
        let line_lower = line.to_lowercase();
        if let Some(pos) = line_lower.find(keyword) {
            let after = line[pos + keyword.len()..].trim();
            // Tomar el siguiente token (número)
            if let Some(end) = after.find(' ') {
                Some(after[..end].trim_matches('{').trim_matches('}').to_string())
            } else {
                Some(after.trim_matches('{').trim_matches('}').to_string())
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_available() {
        let backend = NftablesBackend::new();
        // Este test pasará si nft está instalado
        let result = backend.check_available().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_simple_rule() {
        let backend = NftablesBackend::new();
        let line = "meta l4proto tcp tcp dport 22 accept";
        let rule = backend.parse_rule_line(line, 1);

        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.action, "ACCEPT");
        assert_eq!(rule.protocol, "tcp");
        assert_eq!(rule.port, Some("22".to_string()));
    }

    #[test]
    fn test_parse_drop_rule() {
        let backend = NftablesBackend::new();
        let line = "meta l4proto tcp tcp dport 23 drop";
        let rule = backend.parse_rule_line(line, 1);

        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.action, "DROP");
        assert_eq!(rule.port, Some("23".to_string()));
    }
}
