// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#include <cstring>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "ts_ctrl.h"

namespace {

static const char *const TAG = "ts_main";
static constexpr EventBits_t WIFI_CONNECTED_BIT = BIT0;
static constexpr EventBits_t WIFI_FAILED_BIT = BIT1;
static constexpr int WIFI_MAX_RETRIES = 5;
#ifdef CONFIG_TS_WIRE_INGRESS
static constexpr bool TS_WIRE_INGRESS_ENABLED = true;
#else
static constexpr bool TS_WIRE_INGRESS_ENABLED = false;
#endif
#ifdef CONFIG_TS_INGRESS_ENABLED
static constexpr bool TS_INGRESS_ENABLED = true;
#else
static constexpr bool TS_INGRESS_ENABLED = false;
#endif

EventGroupHandle_t s_wifi_events = nullptr;
TaskHandle_t s_tailscale_task = nullptr;
int s_wifi_retry_count = 0;

bool is_placeholder_(const char *value, const char *prefix) {
  return value == nullptr || value[0] == '\0' || strncmp(value, prefix, strlen(prefix)) == 0;
}

void wifi_event_handler_(void *, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
    return;
  }

  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
    auto *disc = static_cast<wifi_event_sta_disconnected_t *>(event_data);
    xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
    if (s_wifi_retry_count < WIFI_MAX_RETRIES) {
      s_wifi_retry_count++;
      ESP_LOGW(TAG, "WiFi disconnected, reason=%d retry=%d/%d", disc->reason, s_wifi_retry_count, WIFI_MAX_RETRIES);
      esp_wifi_connect();
    } else {
      ESP_LOGE(TAG, "WiFi failed after %d retries", WIFI_MAX_RETRIES);
      xEventGroupSetBits(s_wifi_events, WIFI_FAILED_BIT);
    }
    return;
  }

  if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    auto *event = static_cast<ip_event_got_ip_t *>(event_data);
    s_wifi_retry_count = 0;
    xEventGroupClearBits(s_wifi_events, WIFI_FAILED_BIT);
    xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&event->ip_info.ip));
  }
}

void wifi_init_sta_() {
  s_wifi_events = xEventGroupCreate();

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler_, nullptr, nullptr));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler_, nullptr, nullptr));

  wifi_config_t wifi_config = {};
  std::strncpy(reinterpret_cast<char *>(wifi_config.sta.ssid), CONFIG_TS_WIFI_SSID, sizeof(wifi_config.sta.ssid) - 1);
  std::strncpy(reinterpret_cast<char *>(wifi_config.sta.password), CONFIG_TS_WIFI_PASSWORD,
               sizeof(wifi_config.sta.password) - 1);
  wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

  ESP_LOGI(TAG, "WiFi init complete, connecting to %s", CONFIG_TS_WIFI_SSID);
}

bool run_tailscale_session_() {
  ts_ctrl_t *ctrl = static_cast<ts_ctrl_t *>(heap_caps_calloc(1, sizeof(ts_ctrl_t), MALLOC_CAP_8BIT));
  if (ctrl == nullptr) {
    ESP_LOGE(TAG, "tailscale control allocation failed");
    return false;
  }

  bool ok = false;
  const char *steps[] = {"connect", "handshake", "register", "map", "stream_start"};
  esp_err_t (*calls[])(ts_ctrl_t *) = {
      ts_ctrl_connect,
      ts_ctrl_handshake,
      ts_ctrl_register,
      ts_ctrl_fetch_map,
      ts_ctrl_start_stream,
  };
  ESP_LOGI(TAG, "heap[start] free=%u largest=%u", (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT),
           (unsigned) heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));

  if (ts_ctrl_init(ctrl, CONFIG_TS_AUTH_KEY, CONFIG_TS_DEVICE_NAME, TS_WIRE_INGRESS_ENABLED, TS_INGRESS_ENABLED,
                   static_cast<uint16_t>(CONFIG_TS_ADVERTISED_SERVICE_PORT)) != ESP_OK) {
    ESP_LOGE(TAG, "ts_ctrl_init failed");
    goto cleanup;
  }

  for (size_t index = 0; index < sizeof(calls) / sizeof(calls[0]); index++) {
    ESP_LOGI(TAG, "tailscale step: %s", steps[index]);
    if (calls[index](ctrl) != ESP_OK) {
      ESP_LOGE(TAG, "tailscale step failed: %s", steps[index]);
      goto cleanup;
    }
  }

  ESP_LOGI(TAG, "tailscale connected vpn_ip=%s peers=%d identity=%s machine=%s node=%s", ctrl->vpn_ip, ctrl->peer_count,
           ctrl->identity_status, ctrl->machine_key_id, ctrl->node_key_id);

  while ((xEventGroupGetBits(s_wifi_events) & WIFI_CONNECTED_BIT) != 0) {
    int poll_result = ts_ctrl_poll_stream(ctrl, CONFIG_TS_STREAM_POLL_TIMEOUT_MS);
    if (poll_result < 0) {
      ESP_LOGW(TAG, "tailscale stream ended unexpectedly");
      goto cleanup;
    }
    if (poll_result > 0) {
      ESP_LOGI(TAG, "tailscale live vpn_ip=%s peers=%d identity=%s", ctrl->vpn_ip, ctrl->peer_count, ctrl->identity_status);
    }
  }

  ok = true;

cleanup:
  ts_ctrl_close(ctrl);
  free(ctrl);
  ESP_LOGI(TAG, "heap[end] free=%u largest=%u", (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT),
           (unsigned) heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
  return ok;
}

void tailscale_task_(void *) {
  while (true) {
    EventBits_t bits = xEventGroupWaitBits(s_wifi_events, WIFI_CONNECTED_BIT | WIFI_FAILED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    if ((bits & WIFI_CONNECTED_BIT) == 0) {
      vTaskDelay(pdMS_TO_TICKS(1000));
      continue;
    }

    bool ok = run_tailscale_session_();
    if (!ok) {
      ESP_LOGW(TAG, "tailscale session failed, retrying in %d ms", CONFIG_TS_RETRY_DELAY_MS);
      vTaskDelay(pdMS_TO_TICKS(CONFIG_TS_RETRY_DELAY_MS));
      continue;
    }

    ESP_LOGI(TAG, "tailscale session stopped because WiFi went away, waiting for reconnect");
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

}  // namespace

extern "C" void app_main(void) {
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  if (is_placeholder_(CONFIG_TS_WIFI_SSID, "CHANGE_ME_") || is_placeholder_(CONFIG_TS_WIFI_PASSWORD, "CHANGE_ME_") ||
      is_placeholder_(CONFIG_TS_AUTH_KEY, "CHANGE_ME_")) {
    ESP_LOGE(TAG, "project is not configured yet; set WiFi and Tailscale values via menuconfig before flashing");
    return;
  }

  ESP_LOGI(TAG, "ESP32 Tailscale COR standalone starting");
  ESP_LOGI(TAG, "device_name=%s ingress=%d wire_ingress=%d port=%d", CONFIG_TS_DEVICE_NAME, TS_INGRESS_ENABLED,
           TS_WIRE_INGRESS_ENABLED, CONFIG_TS_ADVERTISED_SERVICE_PORT);

  wifi_init_sta_();

  if (xTaskCreate(&tailscale_task_, "ts_general", 24576, nullptr, 5, &s_tailscale_task) != pdPASS) {
    ESP_LOGE(TAG, "failed to create tailscale task");
  }
}
