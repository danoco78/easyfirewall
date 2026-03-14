use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::app::ViewMode;
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

    pub fn render_frame(
        &self,
        f: &mut Frame,
        view_mode: ViewMode,
        monitoring_stats: Option<&crate::monitor::TrafficStats>,
        history: &crate::history::HistoryLog,
    ) {
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
        self.render_header(f, chunks[0], view_mode);

        // Renderizar contenido principal según la vista
        match view_mode {
            ViewMode::Rules => {
                if self.show_details {
                    self.render_details_view(f, chunks[1]);
                } else {
                    self.render_list_view(f, chunks[1]);
                }
            }
            ViewMode::Monitoring => {
                self.render_monitoring_view(f, chunks[1], monitoring_stats);
            }
            ViewMode::History => {
                self.render_history_view(f, chunks[1], history);
            }
        }

        // Renderizar footer
        self.render_footer(f, chunks[2], view_mode);
    }

    fn render_header(&self, f: &mut Frame, area: Rect, view_mode: ViewMode) {
        let (title, subtitle) = match view_mode {
            ViewMode::Rules => (
                "Firewall Manager",
                "Backend: nftables  Status: Active",
            ),
            ViewMode::Monitoring => (
                "Traffic Monitor",
                "Real-time firewall activity",
            ),
            ViewMode::History => (
                "History Log",
                "Recent operations and changes",
            ),
        };

        let header = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    title,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled("v0.3.0", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled(subtitle, Style::default().fg(Color::Gray)),
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

    fn render_footer(&self, f: &mut Frame, area: Rect, view_mode: ViewMode) {
        let (line1, line2) = match view_mode {
            ViewMode::Rules => (
                "EasyFirewall - Manage your firewall rules safely",
                "a:Add e:Edit d:Del m:Monitor h:History q:Quit",
            ),
            ViewMode::Monitoring => (
                "Traffic Monitor - Blocked packets and activity",
                "r:Refresh m:Back h:History q:Quit",
            ),
            ViewMode::History => (
                "History Log - Recent operations and changes",
                "r:Refresh h:Back m:Monitor q:Quit",
            ),
        };

        let footer = Paragraph::new(vec![
            Line::from(line1),
            Line::from(line2),
        ])
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));

        f.render_widget(footer, area);
    }

    fn render_monitoring_view(&self, f: &mut Frame, area: Rect, stats: Option<&crate::monitor::TrafficStats>) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        // Panel de estadísticas principales
        let main_content = if let Some(stats) = stats {
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        "Blocked Traffic",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Packets: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}", stats.blocked_packets),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Bytes:   ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}", stats.blocked_bytes),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Time Window: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{} seconds", stats.time_window_seconds),
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
                Line::from(""),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled("No monitoring data available.", Style::default().fg(Color::Yellow)),
                ]),
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Press 'r' to refresh.", Style::default().fg(Color::Gray)),
                ]),
                Line::from(""),
                Line::from(""),
            ]
        };

        let main_panel = Paragraph::new(main_content)
            .block(Block::default().borders(Borders::ALL).title("Statistics"))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        f.render_widget(main_panel, chunks[0]);

        // Panel de top IPs y puertos
        let side_content = if let Some(stats) = stats {
            let mut lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        "Top Blocked IPs",
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
            ];

            for (ip, count) in stats.most_blocked_ips.iter().take(5) {
                lines.push(Line::from(vec![
                    Span::raw(format!("  {:15} ", ip)),
                    Span::styled(
                        format!("{} attempts", count),
                        Style::default().fg(Color::Red),
                    ),
                ]));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(
                    "Top Attacked Ports",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(""));

            for (port, count) in stats.most_attacked_ports.iter().take(5) {
                lines.push(Line::from(vec![
                    Span::raw(format!("  {:15} ", port)),
                    Span::styled(
                        format!("{} hits", count),
                        Style::default().fg(Color::Red),
                    ),
                ]));
            }

            lines
        } else {
            vec![
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
            ]
        };

        let side_panel = Paragraph::new(side_content)
            .block(Block::default().borders(Borders::ALL).title("Top Activity"))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        f.render_widget(side_panel, chunks[1]);
    }

    fn render_history_view(&self, f: &mut Frame, area: Rect, history: &crate::history::HistoryLog) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(area);

        // Panel de historial
        let history_content = if history.is_empty() {
            vec![
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled("No history entries yet.", Style::default().fg(Color::Yellow)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Operations will be logged here.", Style::default().fg(Color::Gray)),
                ]),
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
            ]
        } else {
            let mut lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("Recent Operations", Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)),
                ]),
                Line::from(""),
                Line::from(""),
            ];

            for entry in history.entries_ref().iter().rev().take(15) {
                let timestamp = entry.timestamp.format("%H:%M:%S");
                let severity_color = match entry.action.severity() {
                    "ERROR" => Color::Red,
                    "WARNING" => Color::Yellow,
                    _ => Color::Green,
                };

                let action_color = match entry.action.action_type() {
                    "ADD" => Color::Green,
                    "DELETE" => Color::Red,
                    "EDIT" => Color::Yellow,
                    "ERROR" => Color::Red,
                    _ => Color::White,
                };

                lines.push(Line::from(vec![
                    Span::raw(format!("{} ", timestamp)),
                    Span::styled(
                        format!("[{}]", entry.action.action_type()),
                        Style::default().fg(action_color),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        entry.action.display_name(),
                        Style::default().fg(severity_color),
                    ),
                ]));
            }

            lines
        };

        let history_panel = Paragraph::new(history_content)
            .block(Block::default().borders(Borders::ALL).title("History"))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        f.render_widget(history_panel, chunks[0]);

        // Panel de estadísticas de historial
        let stats_content = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("History Statistics", Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::styled("Total Entries: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{}", history.len()),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::styled("Operation Types:", Style::default().fg(Color::Gray)),
            ]),
            Line::from(""),
        ];

        let stats_panel = Paragraph::new(stats_content)
            .block(Block::default().borders(Borders::ALL).title("Stats"))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        f.render_widget(stats_panel, chunks[1]);
    }
}
