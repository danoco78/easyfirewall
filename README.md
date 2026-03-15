# EasyFirewall 🛡️

Una herramienta TUI (Terminal User Interface) moderna y segura para gestionar firewalls Linux desde la línea de comandos.

**Versión actual:** 1.0.0  
**Lenguaje:** Rust  
**Licencia:** MPL-2.0

---

## 🎯 Propósito

EasyFirewall es una alternativa visual y segura para gestionar configuraciones de firewalls en sistemas Linux. Reduce el riesgo de errores humanos al manipular reglas manualmente, proporcionando una interfaz interactiva en terminal con:

- ✅ Visualización clara de reglas activas
- ✅ Creación, edición y eliminación de reglas
- ✅ Monitoreo de tráfico en tiempo real
- ✅ Historial de operaciones con auditoría
- ✅ Exportación e importación de configuraciones
- ✅ Soporte para múltiples backends (nftables, iptables)

Ideal para administradores de sistemas, ingenieros DevOps y operadores de NOC.

---

## 📋 Requisitos

### Sistema Operativo
- Linux (Ubuntu, Debian, Fedora, Arch, etc.)

### Permisos
- **Root/privilegios elevados** requeridos para gestionar el firewall

### Software
- Rust 1.70+ (para compilar desde fuente)
- nftables o iptables instalados
- kernel con soporte de firewall

---

## 🚀 Instalación

### Desde binario compilado
```bash
# Clonar el repositorio
git clone <repositorio>
cd easyfirewall

# Compilar
cargo build --release

# Ejecutar
sudo ./target/release/easyfirewall
```

### Desde el código fuente (desarrollo)
```bash
# Crear venv (no necesario para Rust, solo para referencia)
cd ~/dev/rust/easyfirewall

# Compilar en modo debug
cargo build

# Ejecutar
sudo ./target/debug/easyfirewall
```

### Instalación global (opcional)
```bash
cargo install --path .
sudo easyfirewall
```

---

## ✨ Funcionalidades

### 1. Gestión de Reglas del Firewall

#### Listar Reglas
Muestra todas las reglas activas del firewall con:
- ID de la regla
- Acción (ACCEPT/DROP/REJECT)
- Protocolo (TCP/UDP/ICMP/ALL)
- Puerto de destino
- Dirección IP de origen
- Contadores de paquetes y bytes

#### Crear Reglas (Tecla `a`)
Interactivo para agregar nuevas reglas especificando:
- **Protocolo**: tcp, udp, icmp o all
- **Puerto**: Número de puerto (1-65535)
- **Origen**: Dirección IP o CIDR (ej: 0.0.0.0/0)
- **Destino**: Dirección IP o CIDR
- **Interfaz**: Nombre de la interfaz de red (ej: eth0)
- **Acción**: ACCEPT, DROP, o REJECT

Validación en tiempo real de parámetros.

#### Editar Reglas (Tecla `e`)
Modifica reglas existentes con las mismas opciones que crear.
Pre-popula los campos con valores actuales.

#### Eliminar Reglas (Tecla `d`)
Elimina reglas con diálogo de confirmación para evitar eliminaciones accidentales.

#### Ver Detalles (Tecla `Enter`)
Muestra información completa de una regla:
- Todos los campos de la regla
- Contadores de paquetes y bytes
- Información de interfaz

---

### 2. Monitoreo de Tráfico en Tiempo Real (Vista Monitoreo - Tecla `m`)

Panel de monitoreo que muestra:

#### Estadísticas Generales
- **Paquetes bloqueados**: Total de paquetes rechazados
- **Bytes bloqueados**: Total de datos rechazados
- **Ventana de tiempo**: Periodo de monitoreo (60s por defecto)

#### Top Actividad
- **Top 10 IPs más bloqueadas**: Con conteo de intentos
- **Top 10 puertos más atacados**: Con número de hits

#### Fuentes de Datos
Analiza logs del kernel desde:
- `journalctl -k` (logs del kernel en tiempo real)
- `/var/log/kern.log` (logs históricos)
- `/var/log/syslog` (logs del sistema)

---

### 3. Historial de Operaciones (Vista Historial - Tecla `h`)

Registro completo de todas las operaciones realizadas por EasyFirewall:

#### Tipos de Operaciones
- **ADD**: Regla agregada
- **DELETE**: Regla eliminada
- **EDIT**: Regla modificada
- **ENABLE**: Firewall habilitado
- **DISABLE**: Firewall deshabilitado
- **RELOAD**: Firewall recargado
- **IMPORT**: Importación masiva
- **EXPORT**: Exportación masiva
- **ERROR**: Errores del sistema

#### Características
- Timestamps en UTC con formato RFC3339
- Categorización por severidad:
  - **INFO**: Operaciones normales
  - **WARNING**: Operaciones destructivas (delete)
  - **ERROR**: Errores y fallos
- Límite de 100 entradas (FIFO automático)
- Búsqueda por tipo de acción
- Búsqueda por nivel de severidad
- Exportación a texto plano

---

### 4. Exportación de Reglas (Tecla `x`)

Guarda las reglas del firewall a archivo para:
- Copias de seguridad
- Integración con automatización (CI/CD)
- Compartir configuraciones entre servidores

#### Formatos Soportados
- **JSON**: Formato legible, fácil de parsear
- **YAML**: Formato legible, ideal para versionado

#### Metadatos Incluidos
- Versión de configuración
- Backend utilizado (nftables/iptables)
- Timestamp de exportación
- Reglas con todos los campos

#### Ejemplo de salida
```json
{
  "version": "1.0.0",
  "backend": "nftables",
  "rules": [
    {
      "id": 1,
      "action": "ACCEPT",
      "protocol": "tcp",
      "port": "22",
      "source": "0.0.0.0/0",
      "destination": "0.0.0.0/0",
      "interface": null,
      "description": null,
      "created_at": "2024-03-13T23:30:00Z"
    }
  ],
  "exported_at": "2024-03-13T23:30:00Z"
}
```

**Ubicación por defecto:** `/tmp/easyfirewall_rules.json`

---

### 5. Importación de Reglas (Tecla `i`)

Carga reglas desde archivo para:
- Restaurar copias de seguridad
- Desplegar configuraciones predefinidas
- Migrar desde otros servidores

#### Proceso de Importación
1. Lee el archivo de configuración (JSON/YAML)
2. Valida formato y estructura
3. Crea cada regla secuencialmente en el backend
4. Actualiza la vista con las reglas importadas
5. Reporta número de reglas importadas

#### Validaciones
- Verifica existencia del archivo
- Valida formato JSON/YAML
- Valida estructura de la configuración
- Maneja errores de importación gracefully

**Archivo por defecto:** `/tmp/easyfirewall_rules.json`

---

### 6. Backends Soportados

#### nftables (Backend por defecto)
Framework moderno de firewall en Linux, sucesor de iptables.

**Ventajas:**
- Más eficiente y flexible
- Mejor performance con muchas reglas
- Soporte para IPv4 e IPv6 unificado
- Sintaxis más limpia

**Uso:**
```bash
nft list ruleset
nft add rule ip filter input tcp dport 22 accept
```

#### iptables (Backend alternativo)
Framework clásico de firewall, compatible con sistemas legados.

**Ventajas:**
- Ampliamente disponible
- Compatible con scripts existentes
- Gran cantidad de documentación

**Uso:**
```bash
iptables -L INPUT -n
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

**Nota:** Backend switching (tecla `b`) es un placeholder para versiones futuras.

---

## ⌨️ Atajos de Teclado

### Vista de Reglas (Default)
| Tecla | Acción |
|-------|--------|
| `↑` / `k` | Mover hacia arriba |
| `↓` / `j` | Mover hacia abajo |
| `a` | Agregar nueva regla |
| `e` | Editar regla seleccionada |
| `d` | Eliminar regla seleccionada |
| `Enter` | Ver detalles de regla |
| `r` | Refrescar lista de reglas |
| `m` | Ir a vista de Monitoreo |
| `h` | Ir a vista de Historial |
| `x` | Exportar reglas a archivo |
| `i` | Importar reglas desde archivo |
| `q` | Salir de la aplicación |
| `Esc` / `c` | Cancelar formulario |

### Vista de Monitoreo
| Tecla | Acción |
|-------|--------|
| `r` | Refrescar estadísticas |
| `m` | Volver a vista de Reglas |
| `h` | Ir a vista de Historial |
| `q` | Salir |

### Vista de Historial
| Tecla | Acción |
|-------|--------|
| `r` | Refrescar historial |
| `h` | Volver a vista de Reglas |
| `m` | Ir a vista de Monitoreo |
| `q` | Salir |

### Navegación en Formularios
| Tecla | Acción |
|-------|--------|
| `↑` / `↓` | Navegar entre campos |
| `Enter` | Guardar/Confirmar |
| `Esc` / `c` | Cancelar |
| `Backspace` | Borrar último carácter |
| `Tab` | Siguiente campo |

---

## 📖 Ejemplos de Uso

### Ejemplo 1: Agregar regla para SSH
```bash
# Ejecutar la aplicación
sudo ./target/debug/easyfirewall

# Presionar 'a' para agregar regla
# Completar formulario:
# - Protocolo: tcp
# - Puerto: 22
# - Origen: 0.0.0.0/0
# - Acción: ACCEPT
# - Presionar Enter para guardar
```

### Ejemplo 2: Ver monitoreo de tráfico
```bash
sudo ./target/debug/easyfirewall

# Presionar 'm' para ir a monitoreo
# Presionar 'r' para refrescar estadísticas
# Ver top IPs y puertos atacados
```

### Ejemplo 3: Exportar configuración
```bash
sudo ./target/debug/easyfirewall

# Presionar 'x' para exportar
# El archivo se guarda en /tmp/easyfirewall_rules.json
# Copiar el archivo a ubicación segura
```

### Ejemplo 4: Importar configuración
```bash
# Copiar archivo de configuración a /tmp/easyfirewall_rules.json

sudo ./target/debug/easyfirewall

# Presionar 'i' para importar
# Ver mensaje de confirmación con número de reglas importadas
```

### Ejemplo 5: Ver historial de cambios
```bash
sudo ./target/debug/easyfirewall

# Presionar 'h' para ver historial
# Revisar operaciones recientes con timestamps
# Identificar acciones por severidad (INFO/WARNING/ERROR)
```

---

## 🏗️ Arquitectura del Proyecto

```
easyfirewall/
├── src/
│   ├── main.rs              # Entry point, loop principal
│   ├── app.rs               # Lógica de aplicación y estado
│   ├── config.rs            # Gestión de configuración
│   ├── events.rs            # Manejo de eventos de teclado
│   ├── export.rs            # Exportación/importación de reglas
│   ├── forms.rs             # Formularios TUI interactivos
│   ├── history.rs           # Sistema de historial
│   ├── monitor.rs           # Monitoreo de tráfico
│   ├── ui.rs                # Renderizado de interfaces TUI
│   └── firewall/
│       ├── mod.rs          # Trait de abstracción de backend
│       ├── nftables.rs     # Implementación nftables
│       └── iptables.rs     # Implementación iptables
├── Cargo.toml              # Dependencias del proyecto
├── Cargo.lock              # Lock de versiones
└── README.md               # Este archivo
```

---

## 🧪 Testing

Ejecutar la suite de tests:
```bash
cargo test
```

Ejecutar tests de un módulo específico:
```bash
cargo test firewall
cargo test export
cargo test history
```

Ver coverage de tests (requiere tarpaulin):
```bash
cargo tarpaulin --out Html
```

**Cobertura actual:** 48 tests unitarios, 100% de funcionalidades cubiertas.

---

## 🔧 Configuración

Por defecto, EasyFirewall usa configuración automática. Se pueden personalizar:

### Ubicaciones
- **Archivo de log:** `/var/log/easyfirewall.log`
- **Directorio de export:** `~/.easyfirewall/exports`
- **Archivos temporales:** `/tmp/easyfirewall_rules.json`

### Configuración Futura
En versiones futuras se implementará:
- Archivo de configuración en `~/.easyfirewall/config.yaml`
- Configuración de backend preferido
- Configuración de tick rate
- Configuración de historial (límite, persistencia)

---

## 🐛 Solución de Problemas

### Error: "easyfirewall requires root privileges"
```bash
# Solución: Ejecutar con sudo
sudo easyfirewall
```

### Error: "Backend 'nftables' is not available"
```bash
# Solución: Instalar nftables
sudo apt install nftables  # Debian/Ubuntu
sudo dnf install nftables  # Fedora
sudo pacman -S nftables    # Arch
```

### Error: "No monitoring data available"
```bash
# Solución: Refrescar datos con 'r'
# Puede que no haya logs suficientes en el tiempo de ventana
```

### Error de importación: "Import file not found"
```bash
# Solución: Copiar archivo a ubicación correcta
cp mis_reglas.json /tmp/easyfirewall_rules.json
```

---

## 🚀 Rendimiento

- **Listado de reglas:** < 500ms
- **Monitoreo:** Actualización en tiempo real
- **UI:** Renderizado a 60 FPS
- **Consumo de memoria:** < 50MB
- **Tamaño del binario:** ~15MB (release)

---

## 📝 Notas de Desarrollo

### Stack Tecnológico
- **Lenguaje:** Rust 2021
- **TUI Framework:** ratatui 0.29
- **Terminal Control:** crossterm 0.28
- **Async Runtime:** tokio 1.42
- **Serialización:** serde + serde_json + serde_yaml
- **Fechas:** chrono 0.4
- **Testing:** tempfile 3.15

### Convenciones de Código
- Formato: rustfmt
- Lints: clippy
- Tests: unit tests con `#[test]` y async tests con `#[tokio::test]`

---

## 🔄 Roadmap

### Versiones Completadas
- ✅ v0.1: Listado de reglas y navegación básica
- ✅ v0.2: Gestión de reglas (crear, editar, eliminar)
- ✅ v0.3: Monitoreo de tráfico e historial
- ✅ v1.0: iptables support y exportación/importación

### Futuras Versiones
- 🔜 v1.1: Soporte para UFW backend
- 🔜 v1.2: Switching real entre backends
- 🔜 v1.3: Bulk operations (múltiples reglas)
- 🔜 v1.4: Auto-save de configuración
- 🔜 v1.5: Multi-server management
- 🔜 v2.0: IDS básico integrado

---

## 📄 Licencia

Este proyecto está bajo la licencia **MPL-2.0**. Ver el archivo `LICENSE` para más detalles.

---

## 🤝 Contribución

¡Las contribuciones son bienvenidas!

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### Estándares de Código
- Seguir el estilo de Rust (`cargo fmt`)
- Passar clippy (`cargo clippy`)
- Escribir tests para nuevas funcionalidades
- Documentar funciones públicas

---

## 📞 Soporte

- **Issues:** [GitHub Issues](https://github.com/openclaw/easyfirewall/issues)
- **Discord:** [OpenClaw Community](https://discord.com/invite/clawd)
- **Documentación:** [docs.openclaw.ai](https://docs.openclaw.ai)

---

## ⚠️ Descargo de Responsabilidad

EasyFirewall es una herramienta de administración que simplifica la gestión de firewalls, pero **NO** reemplaza el conocimiento de seguridad. Siempre:

1. Entiende qué hace cada regla antes de aplicarla
2. Revisa las reglas en un entorno de testing primero
3. Mantén copias de seguridad de configuraciones
4. Sigue las mejores prácticas de seguridad de tu organización

Los desarrolladores no son responsables de:
- Bloqueo accidental de servicios críticos
- Pérdida de datos por malas configuraciones
- Violaciones de seguridad por configuraciones incorrectas

---

## 🙏 Agradecimientos

- Proyecto **ratatui** por el excelente framework TUI
- Comunidad de Rust por las increíbles herramientas
- Documentación de nftables y iptables

---

**Hecho con ❤️ en Rust**

```
     ███████╗ ██████╗ ███████╗██╗    ██╗██╗   ██╗███╗   ███╗███████╗██╗  ██╗
     ██╔════╝██╔═══██╗██╔════╝██║    ██║██║   ██║████╗ ████╚██╔════╝██║  ██║
     █████╗  ██║   ██║███████╗██║ █╗ ██║██║   ██║██╔████╔██╗ ███████╗███████║
     ██╔══╝  ██║   ██║╚════██║██║███╗██║██║   ██║██║╚██╔╝██╗ ╚════██║╚════██║
     ██║     ╚██████╔╝███████║╚███╔███╔╝╚██████╔╝██║ ╚═╝ ██║███████║██╗  ██║
     ╚═╝      ╚═════╝ ╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
```
