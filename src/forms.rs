use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use crate::firewall::FirewallRule;

#[derive(Debug, Clone, PartialEq)]
pub enum FormMode {
    AddRule,
    EditRule(usize),
    DeleteConfirm(usize),
}

#[derive(Debug, Clone)]
pub struct FormState {
    pub mode: FormMode,
    pub protocol: String,
    pub port: String,
    pub source: String,
    pub destination: String,
    pub interface: String,
    pub action: String,
    pub current_field: usize,
    pub confirmed: bool,
    pub cancelled: bool,
    pub error_message: Option<String>,
}

impl FormState {
    pub fn new_add() -> Self {
        Self {
            mode: FormMode::AddRule,
            protocol: "tcp".to_string(),
            port: String::new(),
            source: "0.0.0.0/0".to_string(),
            destination: "0.0.0.0/0".to_string(),
            interface: String::new(),
            action: "ACCEPT".to_string(),
            current_field: 0,
            confirmed: false,
            cancelled: false,
            error_message: None,
        }
    }

    pub fn new_edit(rule: &FirewallRule) -> Self {
        Self {
            mode: FormMode::EditRule(rule.id),
            protocol: rule.protocol.clone(),
            port: rule.port.as_deref().unwrap_or("").to_string(),
            source: rule.source.clone(),
            destination: rule.destination.clone(),
            interface: rule.interface.as_deref().unwrap_or("").to_string(),
            action: rule.action.clone(),
            current_field: 0,
            confirmed: false,
            cancelled: false,
            error_message: None,
        }
    }

    pub fn new_delete(rule_id: usize) -> Self {
        Self {
            mode: FormMode::DeleteConfirm(rule_id),
            protocol: String::new(),
            port: String::new(),
            source: String::new(),
            destination: String::new(),
            interface: String::new(),
            action: String::new(),
            current_field: 0,
            confirmed: false,
            cancelled: false,
            error_message: None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.mode,
            FormMode::AddRule | FormMode::EditRule(_) | FormMode::DeleteConfirm(_)
        )
    }

    pub fn get_field_mut(&mut self, index: usize) -> Option<&mut String> {
        match index {
            0 => Some(&mut self.protocol),
            1 => Some(&mut self.port),
            2 => Some(&mut self.source),
            3 => Some(&mut self.destination),
            4 => Some(&mut self.interface),
            5 => Some(&mut self.action),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn get_field_name(index: usize) -> &'static str {
        match index {
            0 => "Protocol",
            1 => "Port",
            2 => "Source",
            3 => "Destination",
            4 => "Interface",
            5 => "Action",
            _ => "",
        }
    }

    pub fn handle_input(&mut self, event: &Event) {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                self.handle_key_event(key);
            }
            _ => {}
        }
    }

    fn handle_key_event(&mut self, key: &KeyEvent) {
        match key.code {
            KeyCode::Up => {
                if self.current_field > 0 {
                    self.current_field -= 1;
                }
            }
            KeyCode::Down => {
                if self.current_field < 5 {
                    self.current_field += 1;
                }
            }
            KeyCode::Char(c) => {
                // Manejar navegación con Tab
                if c == '\t' {
                    if self.current_field < 5 {
                        self.current_field += 1;
                    }
                } else if let Some(field) = self.get_field_mut(self.current_field) {
                    field.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Some(field) = self.get_field_mut(self.current_field) {
                    field.pop();
                }
            }
            KeyCode::Enter => {
                self.confirmed = true;
            }
            KeyCode::Esc => {
                self.cancelled = true;
            }
            _ => {}
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validar protocolo
        let protocol_lower = self.protocol.to_lowercase();
        if !matches!(protocol_lower.as_str(), "tcp" | "udp" | "icmp" | "all") {
            return Err("Protocol must be tcp, udp, icmp, or all".to_string());
        }

        // Validar puerto (si está especificado)
        if !self.port.is_empty() {
            if self.port.parse::<u16>().is_err() {
                return Err("Port must be a valid number (1-65535)".to_string());
            }
        }

        // Validar acción
        let action_upper = self.action.to_uppercase();
        if !matches!(action_upper.as_str(), "ACCEPT" | "DROP" | "REJECT") {
            return Err("Action must be ACCEPT, DROP, or REJECT".to_string());
        }

        Ok(())
    }

    pub fn to_rule(&self, id: usize) -> Option<FirewallRule> {
        if let Err(_e) = self.validate() {
            return None;
        }

        Some(FirewallRule {
            id,
            action: self.action.to_uppercase(),
            protocol: self.protocol.to_lowercase(),
            port: if self.port.is_empty() {
                None
            } else {
                Some(self.port.clone())
            },
            source: if self.source.is_empty() {
                "0.0.0.0/0".to_string()
            } else {
                self.source.clone()
            },
            destination: if self.destination.is_empty() {
                "0.0.0.0/0".to_string()
            } else {
                self.destination.clone()
            },
            interface: if self.interface.is_empty() {
                None
            } else {
                Some(self.interface.clone())
            },
            origin: crate::firewall::RuleOrigin::EasyFirewall,
            packets: 0,
            bytes: 0,
        })
    }
}

pub struct FormRenderer;

impl FormRenderer {
    pub fn render(f: &mut Frame, state: &FormState) {
        let size = f.area();

        // Crear un modal centrado
        let modal_width = std::cmp::min(60, size.width - 4);
        let modal_height = std::cmp::min(20, size.height - 4);
        let x = (size.width - modal_width) / 2;
        let y = (size.height - modal_height) / 2;

        let modal_area = Rect::new(x, y, modal_width, modal_height);

        // Limpiar el área del modal
        f.render_widget(Clear, modal_area);

        match state.mode {
            FormMode::AddRule => Self::render_add_rule(f, modal_area, state),
            FormMode::EditRule(id) => Self::render_edit_rule(f, modal_area, state, id),
            FormMode::DeleteConfirm(id) => Self::render_delete_confirm(f, modal_area, state, id),
        }
    }

    fn render_add_rule(f: &mut Frame, area: Rect, state: &FormState) {
        let title = "Add Firewall Rule";

        let content = vec![
            Line::from(vec![
                Span::styled(
                    title,
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Self::render_field("Protocol", &state.protocol, state.current_field == 0),
            Line::from(""),
            Self::render_field("Port", &state.port, state.current_field == 1),
            Line::from(""),
            Self::render_field("Source", &state.source, state.current_field == 2),
            Line::from(""),
            Self::render_field("Destination", &state.destination, state.current_field == 3),
            Line::from(""),
            Self::render_field("Interface", &state.interface, state.current_field == 4),
            Line::from(""),
            Self::render_field("Action", &state.action, state.current_field == 5),
            Line::from(""),
            Line::from(""),
            if let Some(ref error) = state.error_message {
                Line::from(vec![Span::styled(
                    format!("Error: {}", error),
                    Style::default().fg(Color::Red),
                )])
            } else {
                Line::from(vec![Span::styled(
                    "Enter: Save  Esc: Cancel  ↑/↓: Navigate",
                    Style::default().fg(Color::DarkGray),
                )])
            },
        ];

        let modal = Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        f.render_widget(modal, area);
    }

    fn render_edit_rule(f: &mut Frame, area: Rect, state: &FormState, rule_id: usize) {
        let title = format!("Edit Rule #{}", rule_id);

        let content = vec![
            Line::from(vec![
                Span::styled(
                    title,
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Self::render_field("Protocol", &state.protocol, state.current_field == 0),
            Line::from(""),
            Self::render_field("Port", &state.port, state.current_field == 1),
            Line::from(""),
            Self::render_field("Source", &state.source, state.current_field == 2),
            Line::from(""),
            Self::render_field("Destination", &state.destination, state.current_field == 3),
            Line::from(""),
            Self::render_field("Interface", &state.interface, state.current_field == 4),
            Line::from(""),
            Self::render_field("Action", &state.action, state.current_field == 5),
            Line::from(""),
            Line::from(""),
            if let Some(ref error) = state.error_message {
                Line::from(vec![Span::styled(
                    format!("Error: {}", error),
                    Style::default().fg(Color::Red),
                )])
            } else {
                Line::from(vec![Span::styled(
                    "Enter: Save  Esc: Cancel  ↑/↓: Navigate",
                    Style::default().fg(Color::DarkGray),
                )])
            },
        ];

        let modal = Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        f.render_widget(modal, area);
    }

    fn render_delete_confirm(f: &mut Frame, area: Rect, _state: &FormState, rule_id: usize) {
        let content = vec![
            Line::from(vec![
                Span::styled(
                    "Confirm Delete",
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                format!("Are you sure you want to delete rule #{}?", rule_id),
                Style::default(),
            )]),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::styled("Enter: Confirm", Style::default().fg(Color::Green)),
                Span::raw("  "),
                Span::styled("Esc: Cancel", Style::default().fg(Color::Red)),
            ]),
        ];

        let modal = Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Center);

        f.render_widget(modal, area);
    }

    fn render_field(label: &str, value: &str, is_active: bool) -> Line<'static> {
        let label_style = if is_active {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        let value_style = if is_active {
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };

        Line::from(vec![
            Span::styled(format!("{}: ", label), label_style),
            Span::styled(format!("{}_", value), value_style),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_state_new_add() {
        let form = FormState::new_add();
        assert_eq!(form.mode, FormMode::AddRule);
        assert_eq!(form.protocol, "tcp");
        assert_eq!(form.action, "ACCEPT");
        assert!(!form.confirmed);
    }

    #[test]
    fn test_form_state_validation_valid() {
        let mut form = FormState::new_add();
        form.port = "22".to_string();
        assert!(form.validate().is_ok());
    }

    #[test]
    fn test_form_state_validation_invalid_protocol() {
        let mut form = FormState::new_add();
        form.protocol = "invalid".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_form_state_validation_invalid_port() {
        let mut form = FormState::new_add();
        form.port = "invalid".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_form_state_validation_invalid_action() {
        let mut form = FormState::new_add();
        form.action = "invalid".to_string();
        assert!(form.validate().is_err());
    }

    #[test]
    fn test_form_state_to_rule() {
        let mut form = FormState::new_add();
        form.port = "80".to_string();
        let rule = form.to_rule(1);

        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.id, 1);
        assert_eq!(rule.action, "ACCEPT");
        assert_eq!(rule.port, Some("80".to_string()));
    }

    #[test]
    fn test_form_state_field_navigation() {
        let mut form = FormState::new_add();
        assert_eq!(form.current_field, 0);

        form.current_field = 3;
        if let Some(field) = form.get_field_mut(3) {
            *field = "test".to_string();
        }
        assert_eq!(form.destination, "test");
    }
}
