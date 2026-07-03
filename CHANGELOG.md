# Changelog

All notable changes to the standalone ESP-IDF line are documented in this file.

## v1.0.0 - 2026-07-03

### Added

- first standalone ESP-IDF branch for ESP32 Tailscale COR
- native `idf.py` project structure with `main/`, component `CMakeLists.txt`, and `sdkconfig.defaults`
- WiFi and Tailscale configuration through `menuconfig`
- standalone task loop for connect, register, initial map fetch, and live stream polling
- NVS-based identity persistence without ESPHome preferences

### Changed

- moved the Tailscale protocol implementation into a repository layout suitable for standalone ESP-IDF builds
- replaced the previous ESPHome-specific service description with a generic advertised service description
- documented the repository split between `general` and `esphome`

### Removed

- ESPHome Python registration file from this branch
- ESPHome component wrapper code from this branch
