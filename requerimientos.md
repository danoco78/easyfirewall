# entorno de desarrollo
* la carpeta del proyecto esta creada en ~/dev/rust/easyFirewall
* ya tiene repositorio de git inicializado y tiene una rama main y develop
* empieza a trabajar en la rama develop
* crea una rama basada en develop por cada versiòn que crees del numeral 16. roadmap
* solo cuando todas las pruebas al codigo se ejcuten correctamente y no tengas temas pendientes de una versión, puedes mergear la rama a develop
* no te pases a la siguiente versiòn hasta no estar seguro que terminaste con la versiòn actual y no tienes pendientes.
* ya rust se encuentra instalado en el pc
* el proyecto base ya se genero con el comando cargo init easyfirewall asi que ya puedes trabajar directaente en el desarrollo


# Requerimientos de la Aplicación

**Nombre provisional:** `firewall-tui`
**Tipo:** Aplicación TUI (Terminal User Interface) para Linux
**Lenguaje:** Rust

---

# 1. Introducción

Este documento describe los requerimientos funcionales y no funcionales para una herramienta interactiva en terminal destinada a **gestionar la configuración del firewall en sistemas Linux**.

La aplicación proporcionará una **interfaz visual dentro de la terminal (TUI)** que permita:

* visualizar reglas del firewall
* crear, editar y eliminar reglas
* monitorear tráfico bloqueado
* administrar configuraciones del firewall de manera segura y controlada

El objetivo es ofrecer una alternativa **más segura, visual y manejable que editar reglas manualmente desde la línea de comandos**.

---

# 2. Objetivos del Sistema

La aplicación debe permitir:

1. Administrar reglas del firewall desde una interfaz visual en terminal.
2. Reducir errores humanos al manipular reglas manualmente.
3. Ofrecer visibilidad clara del estado actual del firewall.
4. Permitir auditoría básica de cambios.
5. Ser usable remotamente vía SSH.

---

# 3. Alcance

La aplicación se enfocará en sistemas Linux modernos y soportará inicialmente:

* nftables (backend principal)
* iptables (compatibilidad)
* ufw (opcional)

La herramienta **no reemplaza completamente las utilidades del sistema**, sino que actúa como **capa de administración visual y segura**.

---

# 4. Usuarios Objetivo

### 4.1 Administradores de sistemas

Administran servidores Linux y necesitan visualizar reglas rápidamente.

### 4.2 Ingenieros DevOps

Gestionan infraestructura y seguridad de red.

### 4.3 Operadores de NOC

Necesitan revisar o modificar reglas bajo procedimientos controlados.

---

# 5. Características Principales

## 5.1 Visualización de reglas

La aplicación deberá mostrar:

* lista de reglas activas
* política por defecto
* contadores de paquetes
* interfaces asociadas

Ejemplo de vista:

```
Firewall Manager
Backend: nftables
Interface: eth0

RULES
------------------------------------
1  ACCEPT  TCP   22    0.0.0.0/0
2  ACCEPT  TCP   443   0.0.0.0/0
3  DROP    ALL   *     *
```

---

## 5.2 Crear reglas

El usuario podrá crear reglas especificando:

* protocolo
* puerto
* origen
* destino
* acción (accept / drop / reject)
* interfaz de red

Flujo esperado:

```
Add Rule
Protocol: TCP
Port: 8080
Source: 0.0.0.0/0
Action: ACCEPT
```

---

## 5.3 Editar reglas

El sistema permitirá:

* modificar reglas existentes
* cambiar orden de prioridad
* actualizar acciones o puertos

---

## 5.4 Eliminar reglas

El usuario podrá eliminar reglas existentes con confirmación.

Ejemplo:

```
Delete rule 3?
[Yes] [No]
```

---

## 5.5 Activar / desactivar firewall

Permitir:

* habilitar firewall
* deshabilitar firewall
* recargar configuración

---

## 5.6 Monitoreo en tiempo real (idea avanzada)

La aplicación puede incluir un panel de monitoreo que muestre:

* paquetes bloqueados
* IPs más bloqueadas
* puertos más atacados

Ejemplo:

```
Blocked traffic (last 60s)

IP Address        Attempts
--------------------------
192.168.1.10      45
10.0.0.3          21
```

Esto puede basarse en:

* logs del kernel
* logs del firewall

---

## 5.7 Historial de cambios

Registrar operaciones realizadas por la aplicación:

```
Timestamp           Action
-----------------------------------
10:22:11            Rule added: port 80
10:25:02            Rule deleted: port 23
```

Esto permite auditoría básica.

---

# 6. Interfaz de Usuario (TUI)

La aplicación tendrá una interfaz dividida en paneles.

## Layout inicial

```
┌────────────────────────────────────────┐
│ Firewall Manager                       │
├────────────────────────────────────────┤
│ Backend: nftables  Interface: eth0     │
├───────────────┬────────────────────────┤
│ Rules         │ Rule Details           │
│               │                        │
│ 1 ACCEPT 22   │ Port: 22               │
│ 2 ACCEPT 80   │ Protocol: TCP          │
│ 3 DROP  ALL   │ Source: 0.0.0.0/0      │
│               │                        │
├───────────────┴────────────────────────┤
│ a:Add  e:Edit  d:Delete  r:Reload q:Quit│
└────────────────────────────────────────┘
```

---

# 7. Navegación

El usuario interactuará principalmente con teclado.

Controles básicos:

| Tecla | Acción            |
| ----- | ----------------- |
| ↑ ↓   | navegar reglas    |
| Enter | ver detalles      |
| a     | agregar regla     |
| e     | editar regla      |
| d     | eliminar regla    |
| r     | recargar firewall |
| q     | salir             |

---

# 8. Seguridad

La aplicación requiere privilegios elevados.

Requisitos:

* ejecución con `sudo`
* validación de parámetros
* confirmación antes de operaciones destructivas

Ejemplo:

```
This operation modifies firewall rules.
Continue? [y/N]
```

---

# 9. Manejo de Backends

La aplicación debe abstraer el backend del firewall.

Arquitectura sugerida:

```
FirewallBackend
    |
    |-- nftables
    |-- iptables
    |-- ufw
```

Cada backend debe implementar:

* list_rules()
* add_rule()
* delete_rule()
* apply_changes()

---

# 10. Persistencia

Las reglas deben persistir usando el mecanismo del sistema.

Dependiendo del backend:

* nftables.conf
* iptables-save
* ufw configuration

La aplicación **no debe mantener su propio formato de firewall**.

---

# 11. Registro (Logging)

La aplicación debe registrar eventos como:

* inicio
* cambios en reglas
* errores
* operaciones administrativas

Logs sugeridos:

```
/var/log/firewall-tui.log
```

---

# 12. Manejo de Errores

El sistema debe manejar:

* errores de permisos
* backend no disponible
* reglas inválidas
* fallos al aplicar configuración

Ejemplo de error:

```
Error applying firewall rule.
Reason: invalid port range
```

---

# 13. Requerimientos No Funcionales

## 13.1 Portabilidad

Debe funcionar en:

* Debian
* Ubuntu
* Fedora
* Arch

---

## 13.2 Bajo consumo de recursos

La aplicación debe ser liviana y funcionar en:

* servidores
* entornos SSH
* contenedores

---

## 13.3 Rendimiento

Operaciones como listar reglas deben ejecutarse en menos de:

```
500 ms
```

---

# 14. Requerimientos Técnicos

## Lenguaje

Rust

## Arquitectura TUI

Event loop:

```
input event
   ↓
update state
   ↓
render UI
```

## Módulos sugeridos

```
src
 ├── main.rs
 ├── app.rs
 ├── ui.rs
 ├── events.rs
 ├── firewall
 │     ├── mod.rs
 │     ├── nftables.rs
 │     ├── iptables.rs
 │     └── ufw.rs
 └── config.rs
```

---

# 15. Ideas Avanzadas (Futuras)

## 15.1 Visualización de ataques

Panel que muestre:

* IPs que intentan escanear puertos
* patrones sospechosos

---

## 15.2 Reglas inteligentes

Permitir reglas como:

```
Block IP after 10 failed connections
```

Esto convertiría la herramienta en un **mini IDS básico**.

---

## 15.3 Exportación de reglas

Exportar configuración a:

* JSON
* YAML

Para integración con automatización.

---

## 15.4 Integración con automatización

Permitir ejecutar:

```
firewall-tui --apply config.yaml
```

Esto permitiría usar la herramienta en pipelines.

---

## 15.5 Modo lectura

Modo seguro que solo permita visualizar reglas:

```
firewall-tui --read-only
```

Útil para auditorías.

---

# 16. Roadmap Inicial

## Versión 0.1

* listar reglas
* navegación básica
* soporte nftables

## Versión 0.2

* crear reglas
* eliminar reglas
* edición básica

## Versión 0.3

* monitoreo de tráfico
* historial

## Versión 1.0

* soporte iptables
* exportación de reglas
* estabilidad

---

# 17. Criterios de Éxito

La herramienta será considerada exitosa si:

* permite administrar reglas sin editar archivos manualmente
* reduce errores al configurar firewall
* funciona correctamente en terminal remota
* tiene latencia mínima

---

# 18. Posible Evolución del Proyecto

En el futuro el proyecto podría evolucionar hacia:

* herramienta completa de administración de seguridad
* dashboard de firewall
* integración con SIEM
* gestión multi-servidor

---
