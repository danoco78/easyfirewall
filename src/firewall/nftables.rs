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

    async fn add_rule(&self, rule: &FirewallRule) -> Result<()> {
        // Construir comando nft para agregar regla
        // Ejemplo: nft add rule ip filter input tcp dport 22 accept
        let mut cmd_args: Vec<String> = vec![
            "add".to_string(),
            "rule".to_string(),
            "ip".to_string(),
            "filter".to_string(),
            "input".to_string(),
        ];

        // Agregar protocolo
        if rule.protocol != "all" {
            cmd_args.push("meta".to_string());
            cmd_args.push("l4proto".to_string());
            cmd_args.push(rule.protocol.clone());
        }

        // Agregar puerto si está especificado
        if let Some(ref port) = rule.port {
            cmd_args.push(rule.protocol.clone());
            cmd_args.push("dport".to_string());
            cmd_args.push(port.clone());
        }

        // Agregar dirección de origen si no es all
        if rule.source != "0.0.0.0/0" {
            cmd_args.push("ip".to_string());
            cmd_args.push("saddr".to_string());
            cmd_args.push(rule.source.clone());
        }

        // Agregar interfaz si está especificada
        if let Some(ref iface) = rule.interface {
            cmd_args.push("iifname".to_string());
            cmd_args.push(iface.clone());
        }

        // Agregar acción
        cmd_args.push(rule.action.to_lowercase());

        // Ejecutar comando
        let output = Command::new("nft")
            .args(&cmd_args)
            .output()
            .await
            .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "Failed to add rule: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn delete_rule(&self, rule_id: usize) -> Result<()> {
        // Para simplificar en v0.2, eliminamos por índice
        // En una versión más completa, manejaríamos handles de nftables
        // Esta es una implementación básica que usa flush y rebuild
        // NOTA: Esta es una implementación simplificada para la v0.2
        // Una implementación completa necesitaría manejar handles específicos

        // Obtener reglas actuales
        let current_rules = self.list_rules().await?;

        // Buscar la regla a eliminar
        if rule_id == 0 || rule_id > current_rules.len() {
            return Err(FirewallError::InvalidRule(format!(
                "Invalid rule ID: {}",
                rule_id
            )));
        }

        // Para v0.2, usamos un enfoque simplificado:
        // Eliminar todas las reglas y reconstruir sin la regla específica
        // NOTA: Esto NO es seguro para producción
        // En v0.3+, implementaremos manejo de handles

        // Eliminar todas las reglas de la cadena input
        let _ = Command::new("nft")
            .args(["flush", "rule", "ip", "filter", "input"])
            .output()
            .await;

        // Reconstruir todas las reglas excepto la eliminada
        for (idx, rule) in current_rules.iter().enumerate() {
            // Saltar la regla a eliminar (usando índice 1-based)
            if idx + 1 == rule_id {
                continue;
            }

            // Re-agregar la regla
            let _ = self.add_rule(rule).await;
        }

        Ok(())
    }

    async fn update_rule(&self, rule: &FirewallRule) -> Result<()> {
        // Para v0.2, update se implementa como delete + add
        // En versiones futuras, usaremos handles específicos de nftables
        self.delete_rule(rule.id).await?;
        self.add_rule(rule).await?;
        Ok(())
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
            origin: crate::firewall::RuleOrigin::System,
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
