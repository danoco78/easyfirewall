use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::firewall::FirewallRule;

pub struct AppUi {
    rules: Vec<FirewallRule>,
    selected_rule: Option<usize>,
    show_details: bool,
}

impl AppUi {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            selected_rule: None,
            show_details: false,
        }
    }

    pub fn set_rules(&mut self, rules: Vec<FirewallRule>) {
        self.rules = rules;
    }

    pub fn set_selected_rule(&mut self, index: Option<usize>) {
        self.selected_rule = index;
    }

    pub fn set_show_details(&mut self, show: bool) {
        self.show_details = show;
    }

    pub fn render_frame(&self, f: &mut Frame) {
        let size = f.area();

        // Layout principal
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(0),    // Main content
                Constraint::Length(3), // Footer
            ])
            .split(size);

        // Renderizar header
        self.render_header(f, chunks[0]);

        // Renderizar contenido principal
        if self.show_details {
            self.render_details_view(f, chunks[1]);
        } else {
            self.render_list_view(f, chunks[1]);
        }

        // Renderizar footer
        self.render_footer(f, chunks[2]);
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let header = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    "Firewall Manager",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled("v0.1.0", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("Backend: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "nftables",
                    Style::default().fg(Color::Green),
                ),
                Span::raw("  "),
                Span::styled("Status: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "Active",
                    Style::default().fg(Color::Green),
                ),
            ]),
        ])
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

        f.render_widget(header, area);
    }

    fn render_list_view(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        // Lista de reglas
        let items: Vec<ListItem> = self
            .rules
            .iter()
            .map(|rule| {
                let style = match rule.action.as_str() {
                    "ACCEPT" => Style::default().fg(Color::Green),
                    "DROP" => Style::default().fg(Color::Red),
                    "REJECT" => Style::default().fg(Color::Yellow),
                    _ => Style::default().fg(Color::White),
                };

                ListItem::new(format!(
                    "{:4} {:7} {:6} {:8} {}",
                    rule.id,
                    rule.action,
                    rule.protocol,
                    rule.port.as_deref().unwrap_or("*"),
                    rule.source
                ))
                .style(style)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Rules"))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            );

        let mut list_state = ListState::default();
        if let Some(selected) = self.selected_rule {
            list_state.select(Some(selected));
        }

        f.render_stateful_widget(list, chunks[0], &mut list_state);

        // Panel de ayuda
        let help_text = vec![
            Line::from(""),
            Line::from("Keyboard Shortcuts:"),
            Line::from(""),
            Line::from("  ↑/k    Move up"),
            Line::from("  ↓/j    Move down"),
            Line::from("  Enter  View details"),
            Line::from("  r      Refresh"),
            Line::from("  q      Quit"),
            Line::from(""),
            Line::from(""),
            Line::from("Statistics:"),
            Line::from(format!("  Total rules: {}", self.rules.len())),
        ];

        let help = Paragraph::new(help_text)
            .block(Block::default().borders(Borders::ALL).title("Help"))
            .wrap(Wrap { trim: true });

        f.render_widget(help, chunks[1]);
    }

    fn render_details_view(&self, f: &mut Frame, area: Rect) {
        let details = if let Some(idx) = self.selected_rule {
            if let Some(rule) = self.rules.get(idx) {
                vec![
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Rule Details", Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("ID:       ", Style::default().fg(Color::Gray)),
                        Span::raw(format!("{}", rule.id)),
                    ]),
                    Line::from(vec![
                        Span::styled("Action:   ", Style::default().fg(Color::Gray)),
                        Span::styled(rule.action.clone(), Style::default().fg(Color::Cyan)),
                    ]),
                    Line::from(vec![
                        Span::styled("Protocol: ", Style::default().fg(Color::Gray)),
                        Span::raw(rule.protocol.clone()),
                    ]),
                    Line::from(vec![
                        Span::styled("Port:     ", Style::default().fg(Color::Gray)),
                        Span::raw(rule.port.as_deref().unwrap_or("All").to_string()),
                    ]),
                    Line::from(vec![
                        Span::styled("Source:   ", Style::default().fg(Color::Gray)),
                        Span::raw(rule.source.clone()),
                    ]),
                    Line::from(vec![
                        Span::styled("Dest:     ", Style::default().fg(Color::Gray)),
                        Span::raw(rule.destination.clone()),
                    ]),
                    Line::from(vec![
                        Span::styled("Interface:", Style::default().fg(Color::Gray)),
                        Span::raw(rule.interface.as_deref().unwrap_or("Any").to_string()),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Packets:  ", Style::default().fg(Color::Gray)),
                        Span::raw(format!("{}", rule.packets)),
                    ]),
                    Line::from(vec![
                        Span::styled("Bytes:    ", Style::default().fg(Color::Gray)),
                        Span::raw(format!("{}", rule.bytes)),
                    ]),
                    Line::from(""),
                    Line::from(""),
                    Line::from("Press Enter to return to list view"),
                ]
            } else {
                vec![Line::from("Rule not found"), Line::from("Press Enter to return")]
            }
        } else {
            vec![Line::from("No rule selected"), Line::from("Press Enter to return")]
        };

        let details_panel = Paragraph::new(details)
            .block(Block::default().borders(Borders::ALL).title("Rule Details"))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        f.render_widget(details_panel, area);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let footer = Paragraph::new(vec![
            Line::from("EasyFirewall - Manage your firewall rules safely"),
            Line::from("Press 'h' for help, 'q' to quit"),
        ])
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));

        f.render_widget(footer, area);
    }
}
