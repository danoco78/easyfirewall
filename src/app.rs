use crate::firewall::{FirewallBackend, FirewallRule};
use crate::events::AppEvent;

use anyhow::Result;

pub struct App<B: FirewallBackend> {
    backend: B,
    rules: Vec<FirewallRule>,
    selected_index: usize,
    show_details: bool,
    running: bool,
}

impl<B: FirewallBackend> App<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            rules: Vec::new(),
            selected_index: 0,
            show_details: false,
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
}
