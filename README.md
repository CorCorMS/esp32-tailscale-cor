# ESP32 Tailscale COR

Eigenständiger [Tailscale](https://tailscale.com/) VPN-Client für ESP32-Mikrocontroller.
Implementiert das Tailscale-Control-Protokoll (Noise IK + HTTP/2) direkt auf dem ESP32 – **kein Tailscale-Daemon, keine Linux-Networking-Stack-Emulation**.

## Funktionsumfang

- Noise_IK_25519_ChaChaPoly_BLAKE2s Handshake
- TLS 1.2/1.3 Verbindung zu `controlplane.tailscale.com:443`
- HTTP/2 Frame-Layer (eigene Implementierung)
- Node-Registrierung mit Auth-Key
- Live-Stream des Tailscale Network Map
- Diagnose-Sensoren (VPN-IP, Peer-Count, Verbindungsstatus)

## Voraussetzungen

- **ESP32** (Xtensa LX6) – Original ESP32, ESP32-S2, ESP32-S3
- **ESP-IDF Framework** (Arduino wird nicht unterstützt)
- **8MB Flash** oder PSRAM empfohlen
- **Tailscale Auth-Key** (Pre-Auth-Key) von https://login.tailscale.com/admin/settings/keys

> **Nicht kompatibel:** ESP32-C3, ESP32-C6, ESP32-H2 (RISC-V, nur Xtensa LX6).

## Installation

### Über GitHub (empfohlen)

```yaml
external_components:
  - source:
      type: git
      url: https://github.com/CorCorMS/esp32-tailscale-cor
      ref: v1.0.1
    components: [esp32_tailscale_cor]
```

### Lokaler Ordner

```yaml
external_components:
  - source:
      type: local
      path: components/esp32_tailscale_cor
```

## Konfiguration

### Minimal

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

### Vollständig

```yaml
esp32:
  board: esp32-s3-devkitc-1
  framework:
    type: esp-idf
    sdkconfig_options:
      CONFIG_LWIP_MAX_SOCKETS: "24"
      CONFIG_LWIP_SO_RCVBUF: y
      CONFIG_LWIP_TCPIP_RECVMBOX_SIZE: "64"
      CONFIG_MBEDTLS_HKDF_C: y

psram:
  mode: octal

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password

esp32_tailscale_cor:
  auth_key: !secret tailscale_auth_key
  device_name: wohnzimmer-sensor

  # optionale Sensoren
  connected:
    name: "Tailscale Connected"
  state:
    name: "Tailscale State"
  vpn_ip:
    name: "Tailscale VPN IP"
  peer_count:
    name: "Tailscale Peer Count"
```

### Optionen

| Schlüssel | Typ | Beschreibung |
|---|---|---|
| `auth_key` | **required** | Tailscale Pre-Auth-Key (`tskey-auth-...`) |
| `device_name` | optional | Gerätename im Tailnet (default: ESP-Hostname) |
| `connected` | binary_sensor | `true` wenn VPN-Session aktiv |
| `state` | text_sensor | Aktueller State: `IDLE`, `CONNECT`, `HANDSHAKE`, `REGISTER`, `MAP`, `STREAM`, `WIFI_WAIT`, `ERROR` |
| `vpn_ip` | text_sensor | Tailscale-VPN-IP |
| `peer_count` | sensor | Anzahl verbundener Peer-Nodes |

### SDK-Config (empfohlen)

Folgende Optionen werden per `to_code()` automatisch gesetzt:
- `CONFIG_MBEDTLS_CHACHAPOLY_C = y`
- `CONFIG_MBEDTLS_CHACHA20_C = y`
- `CONFIG_MBEDTLS_POLY1305_C = y`

Optional für größere Tailnets:
- `CONFIG_LWIP_MAX_SOCKETS = 24`
- `CONFIG_LWIP_TCPIP_RECVMBOX_SIZE = 64`

## Kompilierung

Der erste Build dauert länger, da mbedTLS mit ChaCha20/Poly1305 neu kompiliert wird.

```bash
esphome compile esp32-tailscale.yaml
esphome upload esp32-tailscale.yaml
```

## Hinweise

- **Auth-Key im Binary:** Der Key landet im Firmware-Image – `!secret` verwenden, nie ins Repository schreiben.
- **Sensoren aktualisieren** alle 5 Sekunden (konfigurierbar über `update_interval`).
- **State-Machine:** Die Komponente startet automatisch nach WiFi-Verbindung. Bei Fehlern erfolgt ein Retry nach 30 Sekunden.
- **Task-Stack:** 24 KB für den Tailscale-Worker. Bei großen Tailnets (>50 Peers) ggf. erhöhen.

## Projektstruktur

```
esp32_tailscale_cor/
├── __init__.py                  # ESPHome Component Registration
├── esp32_tailscale_cor_component.h/.cpp  # State-Machine + FreeRTOS Task
├── ts_ctrl.h/.cpp              # Tailscale Control Protocol (TLS, Noise, H2)
├── ts_h2.h/.cpp                # HTTP/2 Frame Builder/Parser
├── noise_ik.h/.cpp             # Noise IK Handshake + ChaChaPoly AEAD
├── blake2s.h/.cpp              # BLAKE2s Hash (RFC 7693)
├── x25519.h/.c                 # X25519 ECDH (MIT, strobe-Projekt)
├── LICENSE
└── README.md
```

## Lizenz

**Non-Commercial Use Only** – siehe [LICENSE](LICENSE).

Copyright (c) 2025 CorCorMS

Dieses Repository enthält Drittcode:
- `x25519.h`/`.c` – MIT License, (c) 2015–2016 Cryptography Research, Inc.
- `blake2s.cpp` – basierend auf RFC 7693 (Public Domain)
