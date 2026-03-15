# Changelog

All notable changes to easyfirewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-13

### Added
- Initial release of EasyFirewall
- Terminal User Interface (TUI) for firewall management
- Support for nftables backend
- Rule management: create, edit, delete, and view firewall rules
- Real-time traffic monitoring with statistics
- Top blocked IPs and attacked ports display
- Operation history log with timestamps
- Export rules to JSON and YAML formats
- Import rules from file
- Keyboard navigation with vim-style shortcuts (j/k)
- Form dialogs for rule creation and editing
- Help panel with keyboard shortcuts

### Features
- Multi-view interface (Rules, Monitoring, History)
- Color-coded rule actions (ACCEPT/DROP/REJECT)
- Rule validation with error messages
- Confirm dialogs for destructive operations
- Packet and byte counters per rule
- Time window for monitoring statistics

[Unreleased]: https://github.com/danoco78/easyfirewall/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/danoco78/easyfirewall/releases/tag/v0.1.0
