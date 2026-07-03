# Changelog

All notable changes to this project are documented in this file.

## v1.0.3 - 2026-07-03

### Fixed

- corrected the TLS BIO socket context so ESP32-S2 control-plane reads always operate on the live `ts_ctrl_t` socket instead of a stale integer pointer
- cached and guarded `SO_RCVTIMEO` updates to avoid repeated timeout reconfiguration during TLS reads
- initialized and reset the tracked socket receive-timeout state during connect and close paths for safer reconnect behavior

## v1.0.1 - 2026-07-03

### Changed

- promoted the current working ESP32 Tailscale component into the public release repository
- kept the release scope focused on the ESPHome Tailscale component only, without bundling any local web server setup
- refreshed the repository presentation and documentation to match the cleaner release style used in `ha-energy-native`
- changed the project code license from the previous non-commercial custom license to Apache License 2.0

### Added

- documented the current diagnostic sensors: `identity_status`, `machine_key_id`, and `node_key_id`
- documented the optional ingress advertisement fields: `wire_ingress`, `ingress_enabled`, and `advertised_service_port`
- added `NOTICE` for repository-level attribution and third-party licensing context

### Fixed

- published the newer control-stream implementation that was validated in the latest Home Assistant deployment
- included the current reconnect and identity-persistence behavior used by the working ESP32 build
- aligned the release repository files with the latest working local source instead of the older `v1.0.0` snapshot

## v1.0.0 - 2026-07-02

### Added

- initial public release of ESP32 Tailscale COR
