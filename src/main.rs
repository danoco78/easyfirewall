mod app;
mod config;
mod events;
mod firewall;
mod ui;

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use std::io;
use std::process;

use app::App;
use config::Config;
use events::EventHandler;
use firewall::nftables::NftablesBackend;
use ui::AppUi;

#[tokio::main]
async fn main() -> Result<()> {
    // Verificar permisos de root
    if !check_root() {
        eprintln!("Error: easyfirewall requires root privileges.");
        eprintln!("Please run with: sudo easyfirewall");
        process::exit(1);
    }

    // Cargar configuración
    let config = Config::load()?;

    // Inicializar backend
    let backend = NftablesBackend::new();

    // Crear aplicación
    let mut app = App::new(backend);

    // Inicializar aplicación (verificar backend y cargar reglas)
    if let Err(e) = app.init().await {
        eprintln!("Initialization error: {}", e);
        process::exit(1);
    }

    // Configurar terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend_terminal = CrosstermBackend::new(stdout);

    // Crear UI (sin backend almacenado)
    let mut ui = AppUi::new();

    // Crear terminal y ejecutar
    let mut terminal = ratatui::Terminal::new(backend_terminal)?;

    // Crear manejador de eventos
    let event_handler = EventHandler::new(config.tick_rate_ms);

    // Loop principal
    while app.is_running() {
        // Actualizar UI con el estado actual
        ui.set_rules(app.rules().to_vec());
        ui.set_selected_rule(app.selected_index());
        ui.set_show_details(app.show_details());

        terminal.draw(|f| ui.render_frame(f))?;

        // Esperar evento
        if let Some(event) = event_handler.next().await? {
            // Manejar refresh de reglas
            if event == events::AppEvent::Refresh {
                if let Err(e) = app.load_rules().await {
                    eprintln!("Error refreshing rules: {}", e);
                }
            } else {
                // Manejar otros eventos
                app.handle_event(event);
            }
        }
    }

    // Restaurar terminal
    disable_raw_mode()?;
    execute!(
        io::stdout(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;

    println!("EasyFirewall v0.1.0 - Goodbye!");
    Ok(())
}

fn check_root() -> bool {
    // Verificar si estamos ejecutando como root
    // En Linux/Unix, el usuario root tiene UID 0
    unsafe { libc::geteuid() == 0 }
}
