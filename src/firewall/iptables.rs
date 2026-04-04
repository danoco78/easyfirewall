use super::{FirewallBackend, FirewallError, FirewallRule, Result};
use tokio::process::Command;

pub struct IptablesBackend;

impl IptablesBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IptablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl FirewallBackend for IptablesBackend {
    fn name(&self) -> &str {
        "iptables"
    }

    async fn check_available(&self) -> Result<bool> {
        let output = Command::new("which")
            .arg("iptables")
            .output()
            .await?;

        Ok(output.status.success())
    }

    async fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        let output = Command::new("iptables")
            .args(["-L", "INPUT", "-n", "--line-numbers"])
            .output()
            .await
            .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(stderr.to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_iptables_rules(&stdout)
    }

    async fn add_rule(&self, rule: &FirewallRule) -> Result<()> {
        // Construir comando iptables para agregar regla
        // Ejemplo: iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        let mut cmd_args: Vec<String> = vec![
            "-A".to_string(),
            "INPUT".to_string(),
        ];

        // Agregar protocolo si no es all
        if rule.protocol != "all" {
            cmd_args.push("-p".to_string());
            cmd_args.push(rule.protocol.clone());
        }

        // Agregar puerto si está especificado
        if let Some(ref port) = rule.port {
            cmd_args.push("--dport".to_string());
            cmd_args.push(port.clone());
        }

        // Agregar dirección de origen si no es all
        if rule.source != "0.0.0.0/0" {
            cmd_args.push("-s".to_string());
            cmd_args.push(rule.source.clone());
        }

        // Agregar interfaz si está especificada
        if let Some(ref iface) = rule.interface {
            cmd_args.push("-i".to_string());
            cmd_args.push(iface.clone());
        }

        // Agregar acción
        cmd_args.push("-j".to_string());
        cmd_args.push(rule.action.clone());

        // Ejecutar comando
        let output = Command::new("iptables")
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
        // Para iptables, usamos el número de línea
        if rule_id == 0 {
            return Err(FirewallError::InvalidRule("Invalid rule ID: 0".to_string()));
        }

        // Obtener regla primero
        let rules = self.list_rules().await?;

        if rule_id > rules.len() {
            return Err(FirewallError::InvalidRule(format!(
                "Invalid rule ID: {}",
                rule_id
            )));
        }

        // Obtener la regla actual
        let rule = rules.get(rule_id - 1).ok_or_else(|| {
            FirewallError::InvalidRule(format!("Rule not found: {}", rule_id))
        })?;

        // Construir comando para eliminar
        let mut cmd_args = vec!["-D".to_string(), "INPUT".to_string()];

        if rule.protocol != "all" {
            cmd_args.push("-p".to_string());
            cmd_args.push(rule.protocol.clone());
        }

        if let Some(ref port) = rule.port {
            cmd_args.push("--dport".to_string());
            cmd_args.push(port.clone());
        }

        if rule.source != "0.0.0.0/0" {
            cmd_args.push("-s".to_string());
            cmd_args.push(rule.source.clone());
        }

        if let Some(ref iface) = rule.interface {
            cmd_args.push("-i".to_string());
            cmd_args.push(iface.clone());
        }

        cmd_args.push("-j".to_string());
        cmd_args.push(rule.action.clone());

        // Ejecutar comando
        let output = Command::new("iptables")
            .args(&cmd_args)
            .output()
            .await
            .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "Failed to delete rule: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn update_rule(&self, rule: &FirewallRule) -> Result<()> {
        // Para iptables, update se implementa como delete + add
        // Primero eliminamos la regla existente
        let rule_id = rule.id;

        // Buscar y eliminar la regla por sus parámetros
        let current_rules = self.list_rules().await?;

        // Buscar la regla a actualizar
        for (idx, existing_rule) in current_rules.iter().enumerate() {
            if idx + 1 == rule_id {
                // Eliminar la regla existente
                let mut cmd_args = vec!["-D".to_string(), "INPUT".to_string()];

                if existing_rule.protocol != "all" {
                    cmd_args.push("-p".to_string());
                    cmd_args.push(existing_rule.protocol.clone());
                }

                if let Some(ref port) = existing_rule.port {
                    cmd_args.push("--dport".to_string());
                    cmd_args.push(port.clone());
                }

                if existing_rule.source != "0.0.0.0/0" {
                    cmd_args.push("-s".to_string());
                    cmd_args.push(existing_rule.source.clone());
                }

                if let Some(ref iface) = existing_rule.interface {
                    cmd_args.push("-i".to_string());
                    cmd_args.push(iface.clone());
                }

                cmd_args.push("-j".to_string());
                cmd_args.push(existing_rule.action.clone());

                let _ = Command::new("iptables")
                    .args(&cmd_args)
                    .output()
                    .await;

                break;
            }
        }

        // Agregar la nueva regla
        self.add_rule(rule).await?;

        Ok(())
    }
}

impl IptablesBackend {
    fn parse_iptables_rules(&self, output: &str) -> Result<Vec<FirewallRule>> {
        let mut rules = Vec::new();
        let mut rule_id = 1;

        // Parser básico de iptables -L OUTPUT
        // Ejemplo de línea:
        // 1  ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
        for line in output.lines() {
            let line = line.trim();

            // Ignorar líneas de cabecera
            if line.is_empty()
                || line.starts_with("Chain")
                || line.starts_with("target")
                || line.starts_with("num")
            {
                continue;
            }

            // Parsear línea de regla
            if let Some(rule) = self.parse_rule_line(line, rule_id) {
                rules.push(rule);
                rule_id += 1;
            }
        }

        Ok(rules)
    }

    fn parse_rule_line(&self, line: &str, id: usize) -> Option<FirewallRule> {
        let line = line.trim();

        // Ignorar líneas de cabecera
        if line.is_empty()
            || line.starts_with("Chain")
            || line.starts_with("target")
            || line.starts_with("num")
        {
            return None;
        }

        // Separar por espacios
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 4 {
            return None;
        }

        // Determinar acción
        let action = match parts.get(1).map(|s| s.to_uppercase()) {
            Some(a) if a == "ACCEPT" || a == "DROP" || a == "REJECT" => a,
            _ => "UNKNOWN".to_string(),
        };

        // Determinar protocolo
        let protocol = match parts.get(2) {
            Some(&"tcp") => "tcp".to_string(),
            Some(&"udp") => "udp".to_string(),
            Some(&"icmp") => "icmp".to_string(),
            Some(&"all") => "all".to_string(),
            _ => "all".to_string(),
        };

        // Extraer puerto
        let port = line
            .split("dpt:")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .map(String::from);

        // Origen y destino (default)
        let source = "0.0.0.0/0".to_string();
        let destination = "0.0.0.0/0".to_string();

        // Extraer interfaz
        let interface = line
            .split("in:")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .filter(|s| !s.starts_with('*'))
            .map(String::from);

        Some(FirewallRule {
            id,
            action,
            protocol,
            port,
            source,
            destination,
            interface,
            origin: crate::firewall::RuleOrigin::System,
            packets: 0,
            bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iptables_rule_accept() {
        let backend = IptablesBackend::new();
        let line = "1  ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22";
        let rule = backend.parse_rule_line(line, 1);

        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.action, "ACCEPT");
        assert_eq!(rule.protocol, "tcp");
        assert_eq!(rule.port, Some("22".to_string()));
    }

    #[test]
    fn test_parse_iptables_rule_drop() {
        let backend = IptablesBackend::new();
        let line = "2  DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:23";
        let rule = backend.parse_rule_line(line, 2);

        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.action, "DROP");
        assert_eq!(rule.port, Some("23".to_string()));
    }

    #[test]
    fn test_parse_iptables_rule_with_interface() {
        let backend = IptablesBackend::new();
        let line = "1  ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 in:eth0";
        let rule = backend.parse_rule_line(line, 1);

        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.interface, Some("eth0".to_string()));
    }

    #[test]
    fn test_parse_iptables_ignore_headers() {
        let backend = IptablesBackend::new();

        let header_line = "Chain INPUT (policy ACCEPT)";
        assert!(backend.parse_rule_line(header_line, 1).is_none());

        let header_line2 = "num target prot opt source               destination";
        assert!(backend.parse_rule_line(header_line2, 1).is_none());
    }
}
