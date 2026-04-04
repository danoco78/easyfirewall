use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HistoryAction {
    RuleAdded { id: usize, port: String },
    RuleDeleted { id: usize, port: String },
    RuleEdited { id: usize, port: String },
    FirewallEnabled,
    FirewallDisabled,
    FirewallReloaded,
    BulkImport { count: usize },
    BulkExport { count: usize },
    Error { message: String },
}

impl HistoryAction {
    pub fn display_name(&self) -> String {
        match self {
            HistoryAction::RuleAdded { id, port } => {
                format!("Rule added: #{} port {}", id, port)
            }
            HistoryAction::RuleDeleted { id, port } => {
                format!("Rule deleted: #{} port {}", id, port)
            }
            HistoryAction::RuleEdited { id, port } => {
                format!("Rule edited: #{} port {}", id, port)
            }
            HistoryAction::FirewallEnabled => "Firewall enabled".to_string(),
            HistoryAction::FirewallDisabled => "Firewall disabled".to_string(),
            HistoryAction::FirewallReloaded => "Firewall reloaded".to_string(),
            HistoryAction::BulkImport { count } => {
                format!("Bulk import: {} rules", count)
            }
            HistoryAction::BulkExport { count } => {
                format!("Bulk export: {} rules", count)
            }
            HistoryAction::Error { message } => {
                format!("Error: {}", message)
            }
        }
    }

    pub fn action_type(&self) -> &'static str {
        match self {
            HistoryAction::RuleAdded { .. } => "ADD",
            HistoryAction::RuleDeleted { .. } => "DELETE",
            HistoryAction::RuleEdited { .. } => "EDIT",
            HistoryAction::FirewallEnabled => "ENABLE",
            HistoryAction::FirewallDisabled => "DISABLE",
            HistoryAction::FirewallReloaded => "RELOAD",
            HistoryAction::BulkImport { .. } => "IMPORT",
            HistoryAction::BulkExport { .. } => "EXPORT",
            HistoryAction::Error { .. } => "ERROR",
        }
    }

    pub fn severity(&self) -> &'static str {
        match self {
            HistoryAction::Error { .. } => "ERROR",
            HistoryAction::RuleDeleted { .. } => "WARNING",
            _ => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action: HistoryAction,
}

impl HistoryEntry {
    pub fn new(action: HistoryAction) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            action,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryLog {
    entries: VecDeque<HistoryEntry>,
    max_entries: usize,
    persistent: bool,
    log_file: Option<PathBuf>,
}

impl HistoryLog {
    pub fn new(max_entries: usize, persistent: bool, log_file: Option<PathBuf>) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries),
            max_entries,
            persistent,
            log_file,
        }
    }

    #[allow(dead_code)]
    pub fn default() -> Self {
        Self::new(100, false, None)
    }

    pub fn add(&mut self, action: HistoryAction) {
        let entry = HistoryEntry::new(action);
        self.entries.push_back(entry);

        // Mantener límite máximo
        if self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }

        // Guardar en disco si es persistente
        if self.persistent {
            if let Err(e) = self.save_to_disk() {
                eprintln!("Error saving history: {}", e);
            }
        }
    }

    #[allow(dead_code)]
    pub fn entries(&self) -> &VecDeque<HistoryEntry> {
        &self.entries
    }

    pub fn entries_ref(&self) -> &VecDeque<HistoryEntry> {
        &self.entries
    }

    pub fn recent(&self, count: usize) -> Vec<&HistoryEntry> {
        self.entries.iter().rev().take(count).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        if self.persistent {
            let _ = self.save_to_disk();
        }
    }

    pub fn find_by_action_type(&self, action_type: &str) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.action.action_type() == action_type)
            .collect()
    }

    pub fn find_by_severity(&self, severity: &str) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.action.severity() == severity)
            .collect()
    }

    #[allow(dead_code)]
    pub async fn load_from_disk(&mut self) -> std::io::Result<()> {
        if let Some(ref log_file) = self.log_file {
            use tokio::fs;

            if !log_file.exists() {
                return Ok(()); // No existe, no hay error
            }

            let content = fs::read_to_string(log_file).await?;

            if !content.trim().is_empty() {
                let loaded: VecDeque<HistoryEntry> = serde_json::from_str(&content)
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Failed to parse history: {}", e),
                        )
                    })?;

                self.entries = loaded;
            }
        }

        Ok(())
    }

    pub fn save_to_disk(&self) -> std::io::Result<()> {
        if let Some(ref log_file) = self.log_file {
            // Crear directorio padre si no existe
            if let Some(parent) = log_file.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let json = serde_json::to_string_pretty(&self.entries)?;
            std::fs::write(log_file, json)?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn export_to_file(&self, path: PathBuf) -> std::io::Result<()> {
        use tokio::fs;

        let content = self.format_as_text();
        fs::write(&path, content).await?;

        Ok(())
    }

    pub fn format_as_text(&self) -> String {
        let mut output = String::new();
        output.push_str("EasyFirewall History Log\n");
        output.push_str(&"=".repeat(40));
        output.push('\n');

        for entry in &self.entries {
            output.push_str(&format!(
                "{} | {} | {}\n",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                entry.action.severity(),
                entry.action.display_name()
            ));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_entry_new() {
        let entry = HistoryEntry::new(HistoryAction::RuleAdded {
            id: 1,
            port: "22".to_string(),
        });

        assert_eq!(entry.action.action_type(), "ADD");
        assert_eq!(entry.action.severity(), "INFO");
    }

    #[test]
    fn test_history_log_add() {
        let mut history = HistoryLog::new(100, false, None);

        assert_eq!(history.len(), 0);
        assert!(history.is_empty());

        history.add(HistoryAction::RuleAdded {
            id: 1,
            port: "22".to_string(),
        });

        assert_eq!(history.len(), 1);
        assert!(!history.is_empty());
    }

    #[test]
    fn test_history_log_max_entries() {
        let mut history = HistoryLog::new(5, false, None);

        // Agregar más entradas que el límite
        for i in 0..10 {
            history.add(HistoryAction::RuleAdded {
                id: i,
                port: format!("{}", i),
            });
        }

        // Debe mantener solo las últimas 5
        assert_eq!(history.len(), 5);
    }

    #[test]
    fn test_history_log_recent() {
        let mut history = HistoryLog::new(100, false, None);

        for i in 0..10 {
            history.add(HistoryAction::RuleAdded {
                id: i,
                port: format!("{}", i),
            });
        }

        let recent = history.recent(3);
        assert_eq!(recent.len(), 3);

        // Las más recientes deben tener IDs más altos
        assert_eq!(recent[0].action, HistoryAction::RuleAdded { id: 9, port: "9".to_string() });
    }

    #[test]
    fn test_history_log_find_by_action_type() {
        let mut history = HistoryLog::new(100, false, None);

        history.add(HistoryAction::RuleAdded { id: 1, port: "22".to_string() });
        history.add(HistoryAction::RuleDeleted { id: 1, port: "22".to_string() });
        history.add(HistoryAction::RuleEdited { id: 1, port: "22".to_string() });

        let add_entries = history.find_by_action_type("ADD");
        assert_eq!(add_entries.len(), 1);

        let delete_entries = history.find_by_action_type("DELETE");
        assert_eq!(delete_entries.len(), 1);

        let edit_entries = history.find_by_action_type("EDIT");
        assert_eq!(edit_entries.len(), 1);
    }

    #[test]
    fn test_history_log_find_by_severity() {
        let mut history = HistoryLog::new(100, false, None);

        history.add(HistoryAction::RuleAdded { id: 1, port: "22".to_string() });
        history.add(HistoryAction::RuleDeleted { id: 1, port: "22".to_string() });
        history.add(HistoryAction::Error { message: "Test error".to_string() });

        let info_entries = history.find_by_severity("INFO");
        assert_eq!(info_entries.len(), 1);

        let warning_entries = history.find_by_severity("WARNING");
        assert_eq!(warning_entries.len(), 1);

        let error_entries = history.find_by_severity("ERROR");
        assert_eq!(error_entries.len(), 1);
    }

    #[test]
    fn test_history_log_clear() {
        let mut history = HistoryLog::new(100, false, None);

        history.add(HistoryAction::RuleAdded { id: 1, port: "22".to_string() });
        assert_eq!(history.len(), 1);

        history.clear();
        assert_eq!(history.len(), 0);
        assert!(history.is_empty());
    }

    #[test]
    fn test_history_action_display_name() {
        let action = HistoryAction::RuleAdded { id: 1, port: "22".to_string() };
        assert_eq!(action.display_name(), "Rule added: #1 port 22");

        let action = HistoryAction::RuleDeleted { id: 2, port: "80".to_string() };
        assert_eq!(action.display_name(), "Rule deleted: #2 port 80");

        let action = HistoryAction::FirewallEnabled;
        assert_eq!(action.display_name(), "Firewall enabled");

        let action = HistoryAction::Error { message: "test".to_string() };
        assert_eq!(action.display_name(), "Error: test");
    }

    #[test]
    fn test_history_log_format_as_text() {
        let mut history = HistoryLog::new(100, false, None);

        history.add(HistoryAction::RuleAdded { id: 1, port: "22".to_string() });

        let text = history.format_as_text();

        assert!(text.contains("EasyFirewall History Log"));
        assert!(text.contains("Rule added: #1 port 22"));
    }
}
