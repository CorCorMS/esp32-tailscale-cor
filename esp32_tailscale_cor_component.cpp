// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: LicenseRef-NonCommercial
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#include "esp32_tailscale_cor_component.h"

#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ts_ctrl.h"

#include "esphome/components/network/util.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"

#include <cstring>

namespace esphome {
namespace esp32_tailscale_cor {

static const char *const TAG = "esp32_tailscale_cor";
static TaskHandle_t worker_ = nullptr;

static void worker_fn(void *arg) {
  auto *self = static_cast<ESP32TailscaleCORComponent *>(arg);
  ts_ctrl_t *ctrl = static_cast<ts_ctrl_t *>(heap_caps_calloc(1, sizeof(ts_ctrl_t), MALLOC_CAP_8BIT));
  bool ok = false;

  if (ctrl == nullptr) {
    ESP_LOGE(TAG, "tailscale worker OOM");
    self->set_state(ESP32TailscaleCORComponent::ST_ERROR);
    goto done;
  }

  if (ts_ctrl_init(ctrl, self->auth_key().c_str(), self->device_name().c_str()) != ESP_OK) {
    ESP_LOGE(TAG, "ts_ctrl init failed");
    self->set_state(ESP32TailscaleCORComponent::ST_ERROR);
    goto cleanup;
  }

  self->set_state(ESP32TailscaleCORComponent::ST_HANDSHAKE);
  if (ts_ctrl_connect(ctrl) != ESP_OK) {
    ESP_LOGE(TAG, "tailscale connect failed");
    self->set_state(ESP32TailscaleCORComponent::ST_ERROR);
    goto cleanup;
  }
  if (ts_ctrl_handshake(ctrl) != ESP_OK) {
    ESP_LOGE(TAG, "tailscale handshake failed");
    self->set_state(ESP32TailscaleCORComponent::ST_ERROR);
    goto cleanup;
  }

  self->set_state(ESP32TailscaleCORComponent::ST_REGISTER);
  if (ts_ctrl_register(ctrl) != ESP_OK) {
    ESP_LOGE(TAG, "tailscale register failed");
    self->set_state(ESP32TailscaleCORComponent::ST_ERROR);
    goto cleanup;
  }

  self->set_state(ESP32TailscaleCORComponent::ST_MAP);
  if (ts_ctrl_fetch_map(ctrl) != ESP_OK) {
    ESP_LOGE(TAG, "tailscale initial map failed");
    self->set_state(ESP32TailscaleCORComponent::ST_ERROR);
    goto cleanup;
  }

  self->set_runtime_status(false, ctrl->vpn_ip, ctrl->peer_count);
  if (ts_ctrl_start_stream(ctrl) != ESP_OK) {
    ESP_LOGE(TAG, "tailscale streaming map failed");
    self->set_state(ESP32TailscaleCORComponent::ST_ERROR);
    goto cleanup;
  }

  self->set_state(ESP32TailscaleCORComponent::ST_MAP_STREAM);
  self->set_runtime_status(true, ctrl->vpn_ip, ctrl->peer_count);

  while (!self->stop_requested() && network::is_connected()) {
    int poll_result = ts_ctrl_poll_stream(ctrl, 15000);
    self->set_runtime_status(true, ctrl->vpn_ip, ctrl->peer_count);
    if (poll_result < 0) {
      ESP_LOGW(TAG, "tailscale stream ended unexpectedly");
      self->set_state(ESP32TailscaleCORComponent::ST_ERROR);
      goto cleanup;
    }
  }

  ok = true;

cleanup:
  ts_ctrl_close(ctrl);
  free(ctrl);
  self->clear_runtime_status();
  if (ok) {
    self->set_state(network::is_connected() ? ESP32TailscaleCORComponent::ST_IDLE : ESP32TailscaleCORComponent::ST_WIFI_WAIT);
  }

done:
  worker_ = nullptr;
  vTaskDelete(nullptr);
}

void ESP32TailscaleCORComponent::setup() {
  clear_runtime_status();
  set_state(network::is_connected() ? ST_IDLE : ST_WIFI_WAIT);
}

void ESP32TailscaleCORComponent::loop() {
  if (!network::is_connected()) {
    request_stop();
    if (state_ != ST_WIFI_WAIT) set_state(ST_WIFI_WAIT);
    return;
  }

  if (state_ == ST_WIFI_WAIT && worker_ == nullptr) {
    set_state(ST_IDLE);
  }

  if (state_ == ST_IDLE && state_elapsed_() > 100 && worker_ == nullptr) {
    stop_requested_ = false;
    clear_runtime_status();
    set_state(ST_CONNECT);
    if (xTaskCreate(worker_fn, "ts_cor", 24576, this, 2, &worker_) != pdPASS) {
      ESP_LOGE(TAG, "failed to create tailscale worker");
      set_state(ST_ERROR);
    }
  }

  if (state_ == ST_ERROR && state_elapsed_() > 30000 && worker_ == nullptr) {
    retries_++;
    set_state(ST_IDLE);
  }
}

void ESP32TailscaleCORComponent::update() { publish_diagnostics_(); }

void ESP32TailscaleCORComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "ESP32 Tailscale COR");
  LOG_UPDATE_INTERVAL(this);
}

void ESP32TailscaleCORComponent::set_state(State s) {
  if (s != state_) {
    last_state_ = state_;
    ESP_LOGI(TAG, "%s(%ums)->%s", state_str(last_state_), state_elapsed_(), state_str(s));
  }
  state_ = s;
  state_ms_ = millis();
}

const char *ESP32TailscaleCORComponent::state_str(State s) {
  switch (s) {
    case ST_IDLE:
      return "IDLE";
    case ST_CONNECT:
      return "CONNECT";
    case ST_HANDSHAKE:
      return "HANDSHAKE";
    case ST_REGISTER:
      return "REGISTER";
    case ST_MAP:
      return "MAP";
    case ST_MAP_STREAM:
      return "STREAM";
    case ST_WIFI_WAIT:
      return "WIFI_WAIT";
    case ST_ERROR:
      return "ERROR";
  }
  return "?";
}

uint32_t ESP32TailscaleCORComponent::state_elapsed_() { return millis() - state_ms_; }

void ESP32TailscaleCORComponent::clear_runtime_status() {
  session_live_ = false;
  runtime_peer_count_ = 0;
  std::strncpy(runtime_vpn_ip_, "0.0.0.0", sizeof(runtime_vpn_ip_) - 1);
  runtime_vpn_ip_[sizeof(runtime_vpn_ip_) - 1] = '\0';
}

void ESP32TailscaleCORComponent::set_runtime_status(bool live, const char *vpn_ip, int peer_count) {
  session_live_ = live;
  runtime_peer_count_ = peer_count;
  if (vpn_ip != nullptr && vpn_ip[0] != '\0') {
    std::strncpy(runtime_vpn_ip_, vpn_ip, sizeof(runtime_vpn_ip_) - 1);
    runtime_vpn_ip_[sizeof(runtime_vpn_ip_) - 1] = '\0';
  }
}

void ESP32TailscaleCORComponent::publish_diagnostics_() {
  if (connected_sensor_) connected_sensor_->publish_state(session_live_);
  if (state_sensor_) state_sensor_->publish_state(state_str(state_));
  if (vpn_ip_sensor_) vpn_ip_sensor_->publish_state(runtime_vpn_ip_);
  if (peer_count_sensor_) peer_count_sensor_->publish_state(runtime_peer_count_);
}

}  // namespace esp32_tailscale_cor
}  // namespace esphome
