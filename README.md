# ESP32 Tailscale COR

[![License](https://img.shields.io/github/license/CorCorMS/esp32-tailscale-cor)](https://github.com/CorCorMS/esp32-tailscale-cor/blob/general/LICENSE)

This branch is the standalone ESP-IDF edition of ESP32 Tailscale COR.

It connects an ESP32 directly to a Tailscale tailnet without ESPHome and keeps the Tailscale control implementation on the device itself:

- TLS to `controlplane.tailscale.com:443`
- Noise IK handshake
- HTTP/2 control stream
- node registration with a Tailscale auth key
- persisted local identity in NVS
- live map streaming and serial diagnostics

## Branch layout

This repository now has two product lines:

- `general`: standalone ESP-IDF project without ESPHome
- `esphome`: ESPHome external component line

The existing ESPHome release tags stay on the ESPHome line.
Because Git tags are global across the repository, the standalone line uses its own tag namespace for releases.

## Standalone `1.0.0` scope

This standalone line intentionally includes:

- a native `idf.py` project
- WiFi and auth-key configuration through `menuconfig`
- the current working Tailscale control implementation adapted away from ESPHome preferences
- optional ingress advertisement fields for external Serve/Funnel setups

It intentionally does not include:

- ESPHome YAML
- ESPHome `web_server:`
- bundled Home Assistant dashboards

## Requirements

- ESP32, ESP32-S2, or ESP32-S3
- ESP-IDF 5.5.x
- a Tailscale auth key

Not supported:

- ESP32-C3
- ESP32-C6
- ESP32-H2
- Arduino framework

## Configure

Open the project with ESP-IDF and set your values in `menuconfig`:

```bash
idf.py set-target esp32
idf.py menuconfig
```

Relevant options live under:

`ESP32 Tailscale COR Standalone`

Configure at least:

- `TS_WIFI_SSID`
- `TS_WIFI_PASSWORD`
- `TS_AUTH_KEY`
- `TS_DEVICE_NAME`

Optional:

- `TS_WIRE_INGRESS`
- `TS_INGRESS_ENABLED`
- `TS_ADVERTISED_SERVICE_PORT`

## Build and flash

```bash
idf.py build
idf.py flash monitor
```

## Project structure

```text
components/esp32_tailscale_cor/
main/
CMakeLists.txt
sdkconfig.defaults
```

## Diagnostics

On a successful boot, the serial monitor shows:

- WiFi connect state
- Tailscale identity source
- machine and node key fingerprints
- assigned Tailscale IP
- peer count from the latest map stream

## Release tagging

The standalone line starts at logical version `1.0.0`.
To avoid colliding with the already existing ESPHome tag `v1.0.0`, standalone releases use branch-specific tags such as:

- `general-v1.0.0`

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

Project code in this branch is distributed under Apache License 2.0.

See:

- [LICENSE](LICENSE)
- [NOTICE](NOTICE)
