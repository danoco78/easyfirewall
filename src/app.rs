use crate::firewall::{FirewallBackend, FirewallRule};
use crate::events::AppEvent;
use crate::forms::{FormMode, FormState};
use crate::history::{HistoryAction, HistoryLog};
use crate::monitor::TrafficMonitor;

use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Rules,
    Monitoring,
    History,
}

pub struct App<B: FirewallBackend> {
    backend: B,
    rules: Vec<FirewallRule>,
    selected_index: usize,
    show_details: bool,
    form: Option<FormState>,
    view_mode: ViewMode,
    history: HistoryLog,
    monitor: TrafficMonitor,
    monitoring_stats: Option<crate::monitor::TrafficStats>,
    history_offset: usize,
    running: bool,
}

impl<B: FirewallBackend> App<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            rules: Vec::new(),
            selected_index: 0,
            show_details: false,
            form: None,
            view_mode: ViewMode::Rules,
            history: HistoryLog::new(100, false, None),
            monitor: TrafficMonitor::new("nftables".to_string(), 60),
            monitoring_stats: None,
            history_offset: 0,
            running: true,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub async fn init(&mut self) -> Result<()> {
        // Verificar que el backend esté disponible
        if !self.backend.check_available().await? {
            anyhow::bail!("Backend '{}' is not available", self.backend.name());
        }

        // Cargar reglas iniciales
        self.load_rules().await?;

        Ok(())
    }

    pub async fn load_rules(&mut self) -> Result<()> {
        self.rules = self.backend.list_rules().await?;

        // Ajustar selected_index si está fuera de rango
        if !self.rules.is_empty() && self.selected_index >= self.rules.len() {
            self.selected_index = self.rules.len() - 1;
        }

        Ok(())
    }

    pub fn handle_event(&mut self, event: AppEvent) {
        // Si hay un formulario activo, manejar eventos del formulario
        if self.has_active_form() {
            match event {
                AppEvent::Cancel => {
                    self.cancel_form();
                }
                _ => {
                    // Los otros eventos se manejan en el formulario
                    // La UI pasará los eventos del teclado directamente
                }
            }
            return;
        }

        // Manejar eventos normales de la aplicación
        match event {
            AppEvent::Quit => {
                self.running = false;
            }

            AppEvent::Up => {
                if !self.rules.is_empty() {
                    if self.selected_index > 0 {
                        self.selected_index -= 1;
                    }
                }
            }

            AppEvent::Down => {
                if !self.rules.is_empty() {
                    if self.selected_index < self.rules.len() - 1 {
                        self.selected_index += 1;
                    }
                }
            }

            AppEvent::Enter => {
                if !self.rules.is_empty() {
                    self.show_details = !self.show_details;
                }
            }

            AppEvent::Refresh => {
                // El refresh se maneja en el main loop
            }

            AppEvent::AddRule => {
                self.form = Some(FormState::new_add());
            }

            AppEvent::EditRule => {
                if !self.rules.is_empty() {
                    if let Some(rule) = self.rules.get(self.selected_index) {
                        self.form = Some(FormState::new_edit(rule));
                    }
                }
            }

            AppEvent::DeleteRule => {
                if !self.rules.is_empty() {
                    if let Some(rule) = self.rules.get(self.selected_index) {
                        self.form = Some(FormState::new_delete(rule.id));
                    }
                }
            }

            AppEvent::Cancel => {
                // Cancel form or return to Rules view
                if self.has_active_form() {
                    self.cancel_form();
                } else {
                    // Return to Rules view from any other view
                    self.set_view_mode(ViewMode::Rules);
                }
            }

            AppEvent::ToggleMonitoring => {
                match self.view_mode {
                    ViewMode::Monitoring => {
                        self.set_view_mode(ViewMode::Rules);
                    }
                    _ => {
                        self.set_view_mode(ViewMode::Monitoring);
                    }
                }
            }

            AppEvent::ToggleHistory => {
                match self.view_mode {
                    ViewMode::History => {
                        self.set_view_mode(ViewMode::Rules);
                    }
                    _ => {
                        self.set_view_mode(ViewMode::History);
                    }
                }
            }

            AppEvent::ExportRules => {
                // Manejado en main loop
            }

            AppEvent::ImportRules => {
                // Manejado en main loop
            }

            AppEvent::SwitchBackend => {
                // Manejado en main loop
            }

            AppEvent::Unknown => {
                // Ignorar eventos desconocidos
            }
        }
    }

    pub fn selected_index(&self) -> Option<usize> {
        if self.rules.is_empty() {
            None
        } else {
            Some(self.selected_index)
        }
    }

    pub fn show_details(&self) -> bool {
        self.show_details
    }

    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    #[allow(dead_code)]
    pub fn rules_mut(&mut self) -> &mut Vec<FirewallRule> {
        &mut self.rules
    }

    pub fn has_active_form(&self) -> bool {
        self.form.as_ref().map(|f| f.is_active()).unwrap_or(false)
    }

    pub fn form(&self) -> Option<&FormState> {
        self.form.as_ref()
    }

    pub fn form_mut(&mut self) -> Option<&mut FormState> {
        self.form.as_mut()
    }

    pub async fn save_form(&mut self) -> anyhow::Result<()> {
        if let Some(form) = self.form.take() {
            match form.mode {
                FormMode::AddRule => {
                    if let Err(e) = form.validate() {
                        let mut new_form = form;
                        new_form.error_message = Some(e);
                        new_form.confirmed = false;
                        self.form = Some(new_form);
                        anyhow::bail!("Validation failed");
                    }

                    let new_id = self.rules.len() + 1;
                    if let Some(rule) = form.to_rule(new_id) {
                        let port = rule.port.clone().unwrap_or_else(|| "*".to_string());
                        self.backend.add_rule(&rule).await?;
                        self.load_rules().await?;
                        self.history.add(HistoryAction::RuleAdded {
                            id: new_id,
                            port,
                        });
                    }
                }
                FormMode::EditRule(rule_id) => {
                    if let Err(e) = form.validate() {
                        let mut new_form = form;
                        new_form.error_message = Some(e);
                        new_form.confirmed = false;
                        self.form = Some(new_form);
                        anyhow::bail!("Validation failed");
                    }

                    if let Some(rule) = form.to_rule(rule_id) {
                        let port = rule.port.clone().unwrap_or_else(|| "*".to_string());
                        self.backend.update_rule(&rule).await?;
                        self.load_rules().await?;
                        self.history.add(HistoryAction::RuleEdited {
                            id: rule_id,
                            port,
                        });
                    }
                }
                FormMode::DeleteConfirm(rule_id) => {
                    if form.confirmed {
                        // Buscar port de la regla antes de eliminar
                        let port = self
                            .rules
                            .iter()
                            .find(|r| r.id == rule_id)
                            .and_then(|r| r.port.clone())
                            .unwrap_or_else(|| "*".to_string());

                        self.backend.delete_rule(rule_id).await?;
                        self.load_rules().await?;

                        if self.selected_index >= self.rules.len() && !self.rules.is_empty() {
                            self.selected_index = self.rules.len() - 1;
                        }

                        self.history.add(HistoryAction::RuleDeleted {
                            id: rule_id,
                            port,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub fn cancel_form(&mut self) {
        self.form = None;
    }

    pub fn view_mode(&self) -> ViewMode {
        self.view_mode
    }

    pub fn set_view_mode(&mut self, mode: ViewMode) {
        self.view_mode = mode;
        // Reset detalles cuando cambiamos de vista
        self.show_details = false;
    }

    pub fn history(&self) -> &HistoryLog {
        &self.history
    }

    pub fn history_mut(&mut self) -> &mut HistoryLog {
        &mut self.history
    }

    pub async fn refresh_monitoring(&mut self) -> anyhow::Result<()> {
        match self.monitor.collect_stats().await {
            Ok(stats) => {
                self.monitoring_stats = Some(stats);
                Ok(())
            }
            Err(e) => anyhow::bail!("Failed to collect monitoring stats: {}", e),
        }
    }

    pub fn monitoring_stats(&self) -> Option<&crate::monitor::TrafficStats> {
        self.monitoring_stats.as_ref()
    }

    #[allow(dead_code)]
    pub fn history_offset(&self) -> usize {
        self.history_offset
    }

    #[allow(dead_code)]
    pub fn set_history_offset(&mut self, offset: usize) {
        self.history_offset = offset;
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock backend para testing
    struct MockBackend {
        available: bool,
        rules: Vec<FirewallRule>,
    }

    #[async_trait::async_trait]
    impl FirewallBackend for MockBackend {
        fn name(&self) -> &str {
            "mock"
        }

        async fn check_available(&self) -> std::result::Result<bool, crate::firewall::FirewallError> {
            Ok(self.available)
        }

        async fn list_rules(&self) -> std::result::Result<Vec<FirewallRule>, crate::firewall::FirewallError> {
            Ok(self.rules.clone())
        }

        async fn add_rule(&self, _rule: &FirewallRule) -> std::result::Result<(), crate::firewall::FirewallError> {
            // Mock: no hace nada
            Ok(())
        }

        async fn delete_rule(&self, _rule_id: usize) -> std::result::Result<(), crate::firewall::FirewallError> {
            // Mock: no hace nada
            Ok(())
        }

        async fn update_rule(&self, _rule: &FirewallRule) -> std::result::Result<(), crate::firewall::FirewallError> {
            // Mock: no hace nada
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_app_init_with_unavailable_backend() {
        let backend = MockBackend {
            available: false,
            rules: vec![],
        };
        let mut app = App::new(backend);

        let result = app.init().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not available"));
    }

    #[tokio::test]
    async fn test_app_navigation() {
        let backend = MockBackend {
            available: true,
            rules: vec![
                FirewallRule {
                    id: 1,
                    action: "ACCEPT".to_string(),
                    protocol: "tcp".to_string(),
                    port: Some("22".to_string()),
                    source: "0.0.0.0/0".to_string(),
                    destination: "0.0.0.0/0".to_string(),
                    interface: None,
                    origin: crate::firewall::RuleOrigin::System,
                    packets: 0,
                    bytes: 0,
                },
                FirewallRule {
                    id: 2,
                    action: "DROP".to_string(),
                    protocol: "tcp".to_string(),
                    port: Some("23".to_string()),
                    source: "0.0.0.0/0".to_string(),
                    destination: "0.0.0.0/0".to_string(),
                    interface: None,
                    origin: crate::firewall::RuleOrigin::System,
                    packets: 0,
                    bytes: 0,
                },
                FirewallRule {
                    id: 3,
                    action: "ACCEPT".to_string(),
                    protocol: "tcp".to_string(),
                    port: Some("80".to_string()),
                    source: "0.0.0.0/0".to_string(),
                    destination: "0.0.0.0/0".to_string(),
                    interface: None,
                    origin: crate::firewall::RuleOrigin::System,
                    packets: 0,
                    bytes: 0,
                },
            ],
        };

        let mut app = App::new(backend);
        app.init().await.unwrap();

        // Estado inicial
        assert_eq!(app.selected_index(), Some(0));
        assert_eq!(app.show_details(), false);

        // Navegar hacia abajo
        app.handle_event(AppEvent::Down);
        assert_eq!(app.selected_index(), Some(1));

        app.handle_event(AppEvent::Down);
        assert_eq!(app.selected_index(), Some(2));

        // Intentar ir más allá (no debe cambiar)
        app.handle_event(AppEvent::Down);
        assert_eq!(app.selected_index(), Some(2));

        // Navegar hacia arriba
        app.handle_event(AppEvent::Up);
        assert_eq!(app.selected_index(), Some(1));

        app.handle_event(AppEvent::Up);
        assert_eq!(app.selected_index(), Some(0));

        // Intentar ir más allá (no debe cambiar)
        app.handle_event(AppEvent::Up);
        assert_eq!(app.selected_index(), Some(0));
    }

    #[tokio::test]
    async fn test_app_toggle_details() {
        let backend = MockBackend {
            available: true,
            rules: vec![FirewallRule {
                id: 1,
                action: "ACCEPT".to_string(),
                protocol: "tcp".to_string(),
                port: Some("22".to_string()),
                source: "0.0.0.0/0".to_string(),
                destination: "0.0.0.0/0".to_string(),
                interface: None,
                origin: crate::firewall::RuleOrigin::System,
                packets: 0,
                bytes: 0,
            }],
        };

        let mut app = App::new(backend);
        app.init().await.unwrap();

        assert_eq!(app.show_details(), false);

        app.handle_event(AppEvent::Enter);
        assert_eq!(app.show_details(), true);

        app.handle_event(AppEvent::Enter);
        assert_eq!(app.show_details(), false);
    }

    #[tokio::test]
    async fn test_app_quit() {
        let backend = MockBackend {
            available: true,
            rules: vec![],
        };

        let mut app = App::new(backend);
        app.init().await.unwrap();

        assert_eq!(app.is_running(), true);

        app.handle_event(AppEvent::Quit);
        assert_eq!(app.is_running(), false);
    }

    #[tokio::test]
    async fn test_app_open_add_form() {
        let backend = MockBackend {
            available: true,
            rules: vec![],
        };

        let mut app = App::new(backend);
        app.init().await.unwrap();

        assert_eq!(app.has_active_form(), false);

        app.handle_event(AppEvent::AddRule);

        assert_eq!(app.has_active_form(), true);
        assert!(app.form().is_some());
    }

    #[tokio::test]
    async fn test_app_open_edit_form() {
        let backend = MockBackend {
            available: true,
            rules: vec![FirewallRule {
                id: 1,
                action: "ACCEPT".to_string(),
                protocol: "tcp".to_string(),
                port: Some("22".to_string()),
                source: "0.0.0.0/0".to_string(),
                destination: "0.0.0.0/0".to_string(),
                interface: None,
                origin: crate::firewall::RuleOrigin::System,
                packets: 0,
                bytes: 0,
            }],
        };

        let mut app = App::new(backend);
        app.init().await.unwrap();

        assert_eq!(app.has_active_form(), false);

        app.handle_event(AppEvent::EditRule);

        assert_eq!(app.has_active_form(), true);
        let form = app.form().unwrap();
        assert!(matches!(form.mode, FormMode::EditRule(1)));
    }

    #[tokio::test]
    async fn test_app_open_delete_form() {
        let backend = MockBackend {
            available: true,
            rules: vec![FirewallRule {
                id: 1,
                action: "ACCEPT".to_string(),
                protocol: "tcp".to_string(),
                port: Some("22".to_string()),
                source: "0.0.0.0/0".to_string(),
                destination: "0.0.0.0/0".to_string(),
                interface: None,
                origin: crate::firewall::RuleOrigin::System,
                packets: 0,
                bytes: 0,
            }],
        };

        let mut app = App::new(backend);
        app.init().await.unwrap();

        assert_eq!(app.has_active_form(), false);

        app.handle_event(AppEvent::DeleteRule);

        assert_eq!(app.has_active_form(), true);
        let form = app.form().unwrap();
        assert!(matches!(form.mode, FormMode::DeleteConfirm(1)));
    }

    #[tokio::test]
    async fn test_app_cancel_form() {
        let backend = MockBackend {
            available: true,
            rules: vec![],
        };

        let mut app = App::new(backend);
        app.init().await.unwrap();

        app.handle_event(AppEvent::AddRule);
        assert_eq!(app.has_active_form(), true);

        app.handle_event(AppEvent::Cancel);
        assert_eq!(app.has_active_form(), false);
    }
}
