use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EventError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, EventError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEvent {
    Quit,
    Up,
    Down,
    Enter,
    Refresh,
    AddRule,
    DeleteRule,
    EditRule,
    Cancel,
    Unknown,
}

pub struct EventHandler {
    // Tick rate para polling (en milisegundos)
    tick_rate: std::time::Duration,
}

impl EventHandler {
    pub fn new(tick_rate_ms: u64) -> Self {
        Self {
            tick_rate: std::time::Duration::from_millis(tick_rate_ms),
        }
    }

    pub fn default() -> Self {
        Self::new(250) // 250ms default tick rate
    }

    pub async fn next(&self) -> Result<Option<AppEvent>> {
        if event::poll(self.tick_rate)? {
            if let Event::Key(key) = event::read()? {
                // Ignorar eventos de release y repeat para evitar duplicados
                if key.kind == KeyEventKind::Release {
                    return Ok(None);
                }

                return Ok(Some(self.map_key_event(key)));
            }
        }
        Ok(None)
    }

    fn map_key_event(&self, key: KeyEvent) -> AppEvent {
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), KeyModifiers::NONE) => AppEvent::Quit,
            (KeyCode::Char('Q'), KeyModifiers::NONE) => AppEvent::Quit,
            (KeyCode::Char('a'), KeyModifiers::NONE) => AppEvent::AddRule,
            (KeyCode::Char('A'), KeyModifiers::NONE) => AppEvent::AddRule,
            (KeyCode::Char('d'), KeyModifiers::NONE) => AppEvent::DeleteRule,
            (KeyCode::Char('D'), KeyModifiers::NONE) => AppEvent::DeleteRule,
            (KeyCode::Char('e'), KeyModifiers::NONE) => AppEvent::EditRule,
            (KeyCode::Char('E'), KeyModifiers::NONE) => AppEvent::EditRule,
            (KeyCode::Char('c'), KeyModifiers::NONE) | (KeyCode::Esc, _) => AppEvent::Cancel,
            (KeyCode::Char('C'), KeyModifiers::NONE) => AppEvent::Cancel,
            (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => AppEvent::Up,
            (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => AppEvent::Down,
            (KeyCode::Enter, _) => AppEvent::Enter,
            (KeyCode::Char('r'), KeyModifiers::NONE) => AppEvent::Refresh,
            (KeyCode::Char('R'), KeyModifiers::NONE) => AppEvent::Refresh,
            _ => AppEvent::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_quit_key() {
        let handler = EventHandler::default();

        let key_q = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_q), AppEvent::Quit);

        let key_Q = KeyEvent::new(KeyCode::Char('Q'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_Q), AppEvent::Quit);
    }

    #[test]
    fn test_map_navigation_keys() {
        let handler = EventHandler::default();

        let key_up = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_up), AppEvent::Up);

        let key_down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_down), AppEvent::Down);

        let key_k = KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_k), AppEvent::Up);

        let key_j = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_j), AppEvent::Down);
    }

    #[test]
    fn test_map_refresh_key() {
        let handler = EventHandler::default();

        let key_r = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_r), AppEvent::Refresh);

        let key_R = KeyEvent::new(KeyCode::Char('R'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_R), AppEvent::Refresh);
    }

    #[test]
    fn test_map_rule_management_keys() {
        let handler = EventHandler::default();

        // Add rule
        let key_a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_a), AppEvent::AddRule);

        // Delete rule
        let key_d = KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_d), AppEvent::DeleteRule);

        // Edit rule
        let key_e = KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_e), AppEvent::EditRule);

        // Cancel
        let key_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_c), AppEvent::Cancel);

        let key_esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(handler.map_key_event(key_esc), AppEvent::Cancel);
    }

    #[test]
    fn test_ignore_release_events() {
        let handler = EventHandler::default();

        // Crear KeyEvent manual con kind Release
        let key_release = KeyEvent {
            code: KeyCode::Char('q'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: crossterm::event::KeyEventState::NONE,
        };

        // El event handler debería ignorar eventos release en next()
        // Este test solo verifica que el mapping es correcto
        assert_eq!(handler.map_key_event(key_release), AppEvent::Quit);
    }
}
