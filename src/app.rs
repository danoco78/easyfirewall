use crate::firewall::{FirewallBackend, FirewallRule};
use crate::events::AppEvent;
use crate::forms::{FormMode, FormState};

use anyhow::Result;

pub struct App<B: FirewallBackend> {
    backend: B,
    rules: Vec<FirewallRule>,
    selected_index: usize,
    show_details: bool,
    form: Option<FormState>,
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
                // No hacer nada si no hay formulario activo
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
                    // Validar y crear regla
                    if let Err(e) = form.validate() {
                        // Reinsertar el formulario con el error
                        let mut new_form = form;
                        new_form.error_message = Some(e);
                        new_form.confirmed = false;
                        self.form = Some(new_form);
                        anyhow::bail!("Validation failed");
                    }

                    // Crear nueva regla
                    let new_id = self.rules.len() + 1;
                    if let Some(rule) = form.to_rule(new_id) {
                        self.backend.add_rule(&rule).await?;
                        self.load_rules().await?;
                    }
                }
                FormMode::EditRule(rule_id) => {
                    // Validar y actualizar regla
                    if let Err(e) = form.validate() {
                        let mut new_form = form;
                        new_form.error_message = Some(e);
                        new_form.confirmed = false;
                        self.form = Some(new_form);
                        anyhow::bail!("Validation failed");
                    }

                    if let Some(rule) = form.to_rule(rule_id) {
                        self.backend.update_rule(&rule).await?;
                        self.load_rules().await?;
                    }
                }
                FormMode::DeleteConfirm(rule_id) => {
                    if form.confirmed {
                        self.backend.delete_rule(rule_id).await?;
                        self.load_rules().await?;

                        // Ajustar selected_index si es necesario
                        if self.selected_index >= self.rules.len() && !self.rules.is_empty() {
                            self.selected_index = self.rules.len() - 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn cancel_form(&mut self) {
        self.form = None;
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
