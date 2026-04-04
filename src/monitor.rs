use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockedEntry {
    pub ip_address: String,
    pub port: String,
    pub protocol: String,
    pub attempts: u64,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub blocked_packets: u64,
    pub blocked_bytes: u64,
    pub blocked_entries: Vec<BlockedEntry>,
    pub most_attacked_ports: Vec<(String, u64)>,
    pub most_blocked_ips: Vec<(String, u64)>,
    pub time_window_seconds: u64,
}

impl TrafficStats {
    pub fn new(time_window_seconds: u64) -> Self {
        Self {
            blocked_packets: 0,
            blocked_bytes: 0,
            blocked_entries: Vec::new(),
            most_attacked_ports: Vec::new(),
            most_blocked_ips: Vec::new(),
            time_window_seconds,
        }
    }

    pub fn with_blocked_packets(mut self, count: u64) -> Self {
        self.blocked_packets = count;
        self
    }

    #[allow(dead_code)]
    pub fn with_blocked_bytes(mut self, bytes: u64) -> Self {
        self.blocked_bytes = bytes;
        self
    }

    #[allow(dead_code)]
    pub fn with_blocked_entries(mut self, entries: Vec<BlockedEntry>) -> Self {
        self.blocked_entries = entries;
        self
    }

    #[allow(dead_code)]
    pub fn with_most_attacked_ports(mut self, ports: Vec<(String, u64)>) -> Self {
        self.most_attacked_ports = ports;
        self
    }

    #[allow(dead_code)]
    pub fn with_most_blocked_ips(mut self, ips: Vec<(String, u64)>) -> Self {
        self.most_blocked_ips = ips;
        self
    }
}

#[derive(Debug, Clone)]
pub enum MonitoringError {
    ParseError(String),
    IoError(String),
    #[allow(dead_code)]
    LogFileNotFound(String),
    UnsupportedBackend(String),
}

impl std::fmt::Display for MonitoringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitoringError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            MonitoringError::IoError(e) => write!(f, "IO error: {}", e),
            MonitoringError::LogFileNotFound(path) => write!(f, "Log file not found: {}", path),
            MonitoringError::UnsupportedBackend(backend) => {
                write!(f, "Unsupported backend: {}", backend)
            }
        }
    }
}

impl std::error::Error for MonitoringError {}

impl From<std::io::Error> for MonitoringError {
    fn from(e: std::io::Error) -> Self {
        MonitoringError::IoError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, MonitoringError>;

pub struct TrafficMonitor {
    backend: String,
    time_window: u64,
}

impl TrafficMonitor {
    pub fn new(backend: String, time_window_seconds: u64) -> Self {
        Self {
            backend,
            time_window: time_window_seconds,
        }
    }

    pub async fn collect_stats(&self) -> Result<TrafficStats> {
        match self.backend.as_str() {
            "nftables" => self.collect_nftables_stats().await,
            _ => Err(MonitoringError::UnsupportedBackend(self.backend.clone())),
        }
    }

    async fn collect_nftables_stats(&self) -> Result<TrafficStats> {
        // Leer logs de kernel/iptables
        let mut stats = TrafficStats::new(self.time_window);

        // Intentar leer logs del kernel (dmesg, journalctl, o /var/log)
        match self.read_kernel_logs().await {
            Ok(entries) => {
                // Contar paquetes y bytes bloqueados
                stats.blocked_packets = entries.iter().map(|e| e.attempts).sum();

                // Agrupar por IP
                let mut ip_counts: HashMap<String, u64> = HashMap::new();
                let mut port_counts: HashMap<String, u64> = HashMap::new();

                for entry in &entries {
                    *ip_counts.entry(entry.ip_address.clone()).or_insert(0) += entry.attempts;
                    *port_counts.entry(entry.port.clone()).or_insert(0) += entry.attempts;
                }

                // Top 10 IPs más bloqueadas
                let mut sorted_ips: Vec<(String, u64)> = ip_counts.into_iter().collect();
                sorted_ips.sort_by(|a, b| b.1.cmp(&a.1));
                stats.most_blocked_ips = sorted_ids_into_vec(sorted_ips, 10);

                // Top 10 puertos más atacados
                let mut sorted_ports: Vec<(String, u64)> = port_counts.into_iter().collect();
                sorted_ports.sort_by(|a, b| b.1.cmp(&a.1));
                stats.most_attacked_ports = sorted_ids_into_vec(sorted_ports, 10);

                stats.blocked_entries = entries;
            }
            Err(_) => {
                // Si no podemos leer logs, intentar usar contadores de nftables
                let packet_count = self.get_nftables_counter().await.unwrap_or(0);
                stats.blocked_packets = packet_count;
            }
        }

        Ok(stats)
    }

    async fn read_kernel_logs(&self) -> Result<Vec<BlockedEntry>> {
        use tokio::process::Command;

        // Intentar leer de journalctl
        let output = Command::new("journalctl")
            .args(["-k", "--since", &format!("{}s ago", self.time_window), "-n", "1000"])
            .output()
            .await;

        let entries = match output {
            Ok(result) if result.status.success() => {
                self.parse_kernel_logs(&String::from_utf8_lossy(&result.stdout))
            }
            _ => {
                // Fallback: leer de /var/log/kern.log si existe
                self.read_kern_log_file().await?
            }
        };

        Ok(entries)
    }

    async fn read_kern_log_file(&self) -> Result<Vec<BlockedEntry>> {
        use tokio::fs;

        let paths = vec![
            "/var/log/kern.log",
            "/var/log/syslog",
            "/var/log/messages",
        ];

        for path in paths {
            if let Ok(content) = fs::read_to_string(path).await {
                return Ok(self.parse_kernel_logs(&content));
            }
        }

        Ok(Vec::new())
    }

    fn parse_kernel_logs(&self, log_content: &str) -> Vec<BlockedEntry> {
        let mut ip_counts: HashMap<String, BlockedEntry> = HashMap::new();

        // Parser simple para logs de firewall
        // Buscar patrones como: "IN=eth0 SRC=192.168.1.10 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=22"
        for line in log_content.lines() {
            if let Some(entry) = self.parse_log_line(line) {
                let ip = entry.ip_address.clone();
                if let Some(existing) = ip_counts.get_mut(&ip) {
                    existing.attempts += entry.attempts;
                    existing.last_seen = entry.last_seen;
                } else {
                    ip_counts.insert(ip, entry);
                }
            }
        }

        let mut entries: Vec<BlockedEntry> = ip_counts.into_values().collect();
        entries.sort_by(|a, b| b.attempts.cmp(&a.attempts));

        entries
    }

    fn parse_log_line(&self, line: &str) -> Option<BlockedEntry> {
        let line_lower = line.to_lowercase();

        // Filtrar solo líneas de firewall
        if !line_lower.contains("firewall")
            && !line_lower.contains("drop")
            && !line_lower.contains("reject")
            && !line_lower.contains("block")
        {
            return None;
        }

        // Extraer IP de origen (SRC=)
        let ip_address = extract_log_field(line, "SRC=")
            .or_else(|| extract_log_field(line, "src="))
            .unwrap_or_else(|| "unknown".to_string());

        // Extraer puerto de destino (DPT=)
        let port = extract_log_field(line, "DPT=")
            .or_else(|| extract_log_field(line, "dpt="))
            .unwrap_or_else(|| "unknown".to_string());

        // Extraer protocolo
        let protocol = if line_lower.contains("tcp") {
            "tcp".to_string()
        } else if line_lower.contains("udp") {
            "udp".to_string()
        } else if line_lower.contains("icmp") {
            "icmp".to_string()
        } else {
            "unknown".to_string()
        };

        Some(BlockedEntry {
            ip_address,
            port,
            protocol,
            attempts: 1,
            last_seen: chrono::Utc::now(),
        })
    }

    async fn get_nftables_counter(&self) -> Result<u64> {
        use tokio::process::Command;

        // Contar reglas DROP en la tabla
        let output = Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .await
            .map_err(|e| MonitoringError::IoError(e.to_string()))?;

        if !output.status.success() {
            return Ok(0);
        }

        let content = String::from_utf8_lossy(&output.stdout);
        let drop_count = content.matches("drop").count() as u64;

        Ok(drop_count)
    }
}

fn extract_log_field(line: &str, prefix: &str) -> Option<String> {
    let start = line.find(prefix)?;
    let start = start + prefix.len();

    // Encontrar el final (espacio o fin de línea)
    let end = line[start..]
        .find(|c: char| c.is_whitespace())
        .map(|pos| start + pos)
        .unwrap_or(line.len());

    Some(line[start..end].to_string())
}

fn sorted_ids_into_vec<T>(mut sorted: Vec<(T, u64)>, limit: usize) -> Vec<(T, u64)> {
    sorted.truncate(limit);
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_log_field() {
        let line = "IN=eth0 SRC=192.168.1.10 DST=10.0.0.1 PROTO=TCP DPT=22";
        assert_eq!(
            extract_log_field(line, "SRC="),
            Some("192.168.1.10".to_string())
        );
        assert_eq!(extract_log_field(line, "DPT="), Some("22".to_string()));
    }

    #[test]
    fn test_parse_log_line() {
        let monitor = TrafficMonitor::new("nftables".to_string(), 60);

        let line = "kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.10 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=22";
        let entry = monitor.parse_log_line(line);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.port, "22");
        assert_eq!(entry.protocol, "tcp");
    }

    #[test]
    fn test_traffic_stats_new() {
        let stats = TrafficStats::new(60);

        assert_eq!(stats.blocked_packets, 0);
        assert_eq!(stats.blocked_bytes, 0);
        assert_eq!(stats.time_window_seconds, 60);
        assert!(stats.blocked_entries.is_empty());
    }

    #[test]
    fn test_traffic_stats_with_blocked_packets() {
        let stats = TrafficStats::new(60).with_blocked_packets(100);

        assert_eq!(stats.blocked_packets, 100);
    }

    #[test]
    fn test_parse_kernel_logs() {
        let monitor = TrafficMonitor::new("nftables".to_string(), 60);

        let log_content = "kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.10 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=22
kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.3 DST=192.168.1.1 PROTO=UDP DPT=53";

        let entries = monitor.parse_kernel_logs(log_content);

        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.ip_address == "192.168.1.10"));
        assert!(entries.iter().any(|e| e.ip_address == "10.0.0.3"));
    }
}
