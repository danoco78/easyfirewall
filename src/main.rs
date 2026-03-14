mod app;
mod config;
mod events;
mod export;
mod firewall;
mod forms;
mod history;
mod monitor;
mod ui;

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use std::io;
use std::process;

use app::App;
use config::Config;
use events::EventHandler;
use export::ExportedRule;
use export::RuleExporter;
use firewall::nftables::NftablesBackend;
use firewall::iptables::IptablesBackend;
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

        terminal.draw(|f| {
            ui.render_frame(
                f,
                app.view_mode(),
                app.monitoring_stats(),
                app.history(),
            );
            // Renderizar formulario si está activo
            if let Some(form) = app.form() {
                forms::FormRenderer::render(f, form);
            }
        })?;

        // Esperar evento
        if let Some(event) = event_handler.next().await? {
            // Si hay un formulario activo, manejar eventos de teclado directamente
            if app.has_active_form() {
                // Leer evento de teclado crudo
                if let Ok(key_event) = crossterm::event::read() {
                    if let Some(form) = app.form_mut() {
                        form.handle_input(&key_event);

                        // Chequear si el formulario confirmó
                        if form.confirmed {
                            if let Err(e) = app.save_form().await {
                                // Error guardando el formulario
                                eprintln!("Error saving form: {}", e);
                            }
                        }
                    }
                }
            } else {
                // Manejar eventos normales de la aplicación
                // Manejar refresh de reglas o monitoreo
                if event == events::AppEvent::Refresh {
                    match app.view_mode() {
                        app::ViewMode::Rules => {
                            if let Err(e) = app.load_rules().await {
                                eprintln!("Error refreshing rules: {}", e);
                            }
                        }
                        app::ViewMode::Monitoring => {
                            if let Err(e) = app.refresh_monitoring().await {
                                eprintln!("Error refreshing monitoring: {}", e);
                            }
                        }
                        app::ViewMode::History => {
                            // Historial se actualiza automáticamente
                        }
                    }
                } else if event == events::AppEvent::ExportRules {
                    if let Err(e) = handle_export_rules(&app).await {
                        eprintln!("Error exporting rules: {}", e);
                    }
                } else if event == events::AppEvent::ImportRules {
                    if let Err(e) = handle_import_rules(&mut app).await {
                        eprintln!("Error importing rules: {}", e);
                    }
                } else if event == events::AppEvent::SwitchBackend {
                    eprintln!("Backend switching not yet implemented");
                } else {
                    // Manejar otros eventos
                    app.handle_event(event);
                }
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

async fn handle_export_rules<B>(app: &App<B>) -> anyhow::Result<()>
where
    B: crate::firewall::FirewallBackend,
{
    let export_path = std::path::PathBuf::from("/tmp/easyfirewall_rules.json");

    RuleExporter::export_rules(app.rules(), "nftables", &export_path).await?;

    println!("Rules exported to: {}", export_path.display());

    Ok(())
}

async fn handle_import_rules<B>(app: &mut App<B>) -> anyhow::Result<()>
where
    B: crate::firewall::FirewallBackend,
{
    let import_path = std::path::PathBuf::from("/tmp/easyfirewall_rules.json");

    if !import_path.exists() {
        anyhow::bail!("Import file not found: {}", import_path.display());
    }

    let imported_rules: Vec<ExportedRule> = RuleExporter::import_rules(&import_path).await?;
    let rules_count = imported_rules.len();

    println!("Importing {} rules...", rules_count);

    for exported_rule in imported_rules {
        let rule = crate::firewall::FirewallRule {
            id: app.rules().len() + 1,
            action: exported_rule.action,
            protocol: exported_rule.protocol,
            port: exported_rule.port,
            source: exported_rule.source,
            destination: exported_rule.destination,
            interface: exported_rule.interface,
            packets: 0,
            bytes: 0,
        };

        if let Err(e) = app.backend().add_rule(&rule).await {
            eprintln!("Error importing rule: {}", e);
        }
    }

    app.load_rules().await?;

    println!("Imported {} rules", rules_count);

    Ok(())
}

fn check_root() -> bool {
    // Verificar si estamos ejecutando como root
    // En Linux/Unix, el usuario root tiene UID 0
    unsafe { libc::geteuid() == 0 }
}
