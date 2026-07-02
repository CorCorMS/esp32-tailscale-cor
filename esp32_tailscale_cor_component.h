// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: LicenseRef-NonCommercial
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#pragma once
#include <string>
#include "esphome/core/component.h"
#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"

namespace esphome {
namespace esp32_tailscale_cor {

class ESP32TailscaleCORComponent : public PollingComponent {
 public:
  enum State { ST_IDLE, ST_CONNECT, ST_HANDSHAKE, ST_REGISTER, ST_MAP, ST_MAP_STREAM, ST_WIFI_WAIT, ST_ERROR };
  void set_state(State s);
  const char *state_str(State s);

  void setup() override;
  void loop() override;
  void update() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void set_auth_key(const std::string &key) { auth_key_ = key; }
  void set_device_name(const std::string &name) { device_name_ = name; }

  const std::string &auth_key() const { return auth_key_; }
  const std::string &device_name() const { return device_name_; }
  void set_connected_sensor(binary_sensor::BinarySensor *s) { connected_sensor_ = s; }
  void set_state_sensor(text_sensor::TextSensor *s) { state_sensor_ = s; }
  void set_vpn_ip_sensor(text_sensor::TextSensor *s) { vpn_ip_sensor_ = s; }
  void set_peer_count_sensor(sensor::Sensor *s) { peer_count_sensor_ = s; }
  void request_stop() { stop_requested_ = true; }
  bool stop_requested() const { return stop_requested_; }
  void clear_runtime_status();
  void set_runtime_status(bool live, const char *vpn_ip, int peer_count);

 protected:
  void publish_diagnostics_();
  uint32_t state_elapsed_();

  std::string auth_key_;
  std::string device_name_;
  State state_{ST_IDLE};
  State last_state_{ST_IDLE};
  uint32_t state_ms_{0};
  int retries_{0};
  volatile bool session_live_{false};
  volatile bool stop_requested_{false};
  int runtime_peer_count_{0};
  char runtime_vpn_ip_[64]{};

  binary_sensor::BinarySensor *connected_sensor_{nullptr};
  text_sensor::TextSensor *state_sensor_{nullptr};
  text_sensor::TextSensor *vpn_ip_sensor_{nullptr};
  sensor::Sensor *peer_count_sensor_{nullptr};
};

}  // namespace esp32_tailscale_cor
}  // namespace esphome
