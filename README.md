# ESP32 Tailscale COR

[![GitHub Release](https://img.shields.io/github/v/release/CorCorMS/esp32-tailscale-cor)](https://github.com/CorCorMS/esp32-tailscale-cor/releases)
[![License](https://img.shields.io/badge/license-PolyForm%20NC%201.0.0-red)](https://github.com/CorCorMS/esp32-tailscale-cor/blob/main/LICENSE)

ESP32 Tailscale COR is a native ESPHome external component that connects an ESP32 device directly to a Tailscale tailnet.

It implements the Tailscale control-plane flow on the ESP32 itself:

- TLS to `controlplane.tailscale.com:443`
- Noise IK handshake
- HTTP/2 control stream handling
- node registration with an auth key
- live network-map stream updates
- diagnostic sensors for connection and identity state

## What `v1.0.3` includes

- the current working Tailscale component without any bundled local web UI
- the validated control-stream fixes used in the latest real-device HA deployment
- a receive-timeout handling fix for ESP32-S2 control-plane TLS reads to avoid repeated socket timeout corruption
- identity persistence and identity diagnostics for reconnect visibility
- optional ingress advertisement fields for YAML-driven Serve/Funnel setups

This release does not ship a local HTTP server, HTML dashboard, or an ESPHome `web_server:` block.
If you want HTTP content on the device, keep that in your own ESPHome YAML and advertise the port separately.

## Supported targets

- ESP32
- ESP32-S2
- ESP32-S3
- ESP-IDF framework only

Not supported:

- ESP32-C3
- ESP32-C6
- ESP32-H2
- Arduino framework

## Install with ESPHome

### Git source

```yaml
external_components:
  - source:
      type: git
      url: https://github.com/CorCorMS/esp32-tailscale-cor
      ref: v1.0.3
      path: components
    components: [esp32_tailscale_cor]
```

### Local source

```yaml
external_components:
  - source:
      type: local
      path: /path/to/esp32-tailscale-cor/components
    components: [esp32_tailscale_cor]
```

## Minimal configuration

```yaml
esp32:
  board: esp32dev
  framework:
    type: esp-idf

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password

esp32_tailscale_cor:
  auth_key: !secret tailscale_auth_key
```

## Example with diagnostics and ingress advertisement

```yaml
esp32_tailscale_cor:
  auth_key: !secret tailscale_auth_key
  device_name: esp32-tailscale-cor-test
  wire_ingress: true
  ingress_enabled: true
  advertised_service_port: 80

  connected:
    name: "Tailscale Connected"
  state:
    name: "Tailscale State"
  vpn_ip:
    name: "Tailscale VPN IP"
  peer_count:
    name: "Tailscale Peer Count"
  identity_status:
    name: "Tailscale Identity Status"
  machine_key_id:
    name: "Tailscale Machine Key ID"
  node_key_id:
    name: "Tailscale Node Key ID"
```

## Configuration options

| Key | Type | Description |
| --- | --- | --- |
| `auth_key` | required | Tailscale auth key |
| `device_name` | optional | Tailnet machine name override |
| `wire_ingress` | optional bool | Enables ingress advertising fields in the node registration payload |
| `ingress_enabled` | optional bool | Marks the node as ingress-capable for upstream policy handling |
| `advertised_service_port` | optional port | Port number to advertise for an externally provided local service |
| `connected` | optional binary sensor | Live tailnet connectivity state |
| `state` | optional text sensor | Internal component state machine state |
| `vpn_ip` | optional text sensor | Assigned Tailscale IP |
| `peer_count` | optional sensor | Peer count from the latest map state |
| `identity_status` | optional text sensor | Identity persistence status such as `loaded_nvs` |
| `machine_key_id` | optional text sensor | Short machine-key fingerprint for diagnostics |
| `node_key_id` | optional text sensor | Short node-key fingerprint for diagnostics |

## Build notes

The component enables the required mbedTLS ChaCha20/Poly1305 options automatically through ESPHome.

For larger tailnets, these ESP-IDF settings can help:

- `CONFIG_LWIP_MAX_SOCKETS = 24`
- `CONFIG_LWIP_TCPIP_RECVMBOX_SIZE = 64`
- `CONFIG_LWIP_SO_RCVBUF = y`

## Release scope

This repository intentionally contains only the Tailscale ESPHome component.

Out of scope for this release:

- ESPHome `web_server:` configuration
- device-local HTML or CSS assets
- bundled Home Assistant dashboards

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

The original project code in this repository is source-available under the
PolyForm Noncommercial License 1.0.0.

Commercial use of that original project code is not permitted under this license.

See:

- [LICENSE](LICENSE)
- [NOTICE](NOTICE)

Third-party code remains under its original terms:

- `x25519.c` and `x25519.h`: MIT
- `blake2s.cpp`: RFC 7693 reference / public-domain-compatible basis
