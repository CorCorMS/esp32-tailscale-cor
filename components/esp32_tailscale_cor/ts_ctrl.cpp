// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#include "ts_ctrl.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "nvs.h"
#include "noise_ik.h"
#include "ts_h2.h"

#include <errno.h>
#include <inttypes.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *const TAG = "ts_ctrl";

static constexpr size_t TSC_HTTP_BUF = 4096;
static constexpr size_t TSC_FRAME_BUF = 18 * 1024;
static constexpr size_t TSC_RESP_MAX = 40 * 1024;
static constexpr size_t TSC_PROACTIVE_MAX = 1024;
static constexpr const char *SERVER_HOST = "controlplane.tailscale.com";
static constexpr uint16_t SERVER_PORT = 443;
static constexpr const char *H2_SCHEME = "https";
static constexpr uint16_t DEFAULT_DERP_REGION = 9;
static constexpr uint32_t IDENTITY_PREF_MAGIC = 0x54534331UL;
static constexpr const char *IDENTITY_PREF_NAMESPACE = "ts_cor";
static constexpr const char *IDENTITY_PREF_KEY = "identity_v1";

struct saved_identity_t {
  uint32_t magic;
  uint8_t machine_key_private[32];
  uint8_t node_key_private[32];
  uint8_t disco_key_private[32];
};

namespace {

static bool has_nonzero_bytes(const uint8_t *data, size_t len) {
  for (size_t index = 0; index < len; index++) {
    if (data[index] != 0) return true;
  }
  return false;
}

static bool is_saved_identity_valid(const saved_identity_t &saved, const char **reason) {
  if (saved.magic != IDENTITY_PREF_MAGIC) {
    if (reason != nullptr) *reason = "bad_magic";
    return false;
  }
  if (!has_nonzero_bytes(saved.machine_key_private, sizeof(saved.machine_key_private))) {
    if (reason != nullptr) *reason = "zero_machine";
    return false;
  }
  if (!has_nonzero_bytes(saved.node_key_private, sizeof(saved.node_key_private))) {
    if (reason != nullptr) *reason = "zero_node";
    return false;
  }
  if (!has_nonzero_bytes(saved.disco_key_private, sizeof(saved.disco_key_private))) {
    if (reason != nullptr) *reason = "zero_disco";
    return false;
  }
  if (reason != nullptr) *reason = "ok";
  return true;
}

static void derive_public_keys(ts_ctrl_t *ctrl) {
  noise_ik_generate_keypair(ctrl->machine_key_private, ctrl->machine_key_public);
  noise_ik_generate_keypair(ctrl->node_key_private, ctrl->node_key_public);
  noise_ik_generate_keypair(ctrl->disco_key_private, ctrl->disco_key_public);
}

static void apply_saved_identity(ts_ctrl_t *ctrl, const saved_identity_t &saved) {
  memcpy(ctrl->machine_key_private, saved.machine_key_private, sizeof(ctrl->machine_key_private));
  memcpy(ctrl->node_key_private, saved.node_key_private, sizeof(ctrl->node_key_private));
  memcpy(ctrl->disco_key_private, saved.disco_key_private, sizeof(ctrl->disco_key_private));
  derive_public_keys(ctrl);
}

static void set_key_id(const uint8_t *public_key, char *out, size_t out_size) {
  char key_hex[65];
  static const char hex[] = "0123456789abcdef";
  for (size_t index = 0; index < 32; index++) {
    key_hex[index * 2] = hex[(public_key[index] >> 4) & 0x0F];
    key_hex[index * 2 + 1] = hex[public_key[index] & 0x0F];
  }
  key_hex[64] = '\0';
  snprintf(out, out_size, "%.16s", key_hex);
}

static void update_identity_debug(ts_ctrl_t *ctrl, const char *identity_status) {
  snprintf(ctrl->identity_status, sizeof(ctrl->identity_status), "%s", identity_status != nullptr ? identity_status : "unknown");
  set_key_id(ctrl->machine_key_public, ctrl->machine_key_id, sizeof(ctrl->machine_key_id));
  set_key_id(ctrl->node_key_public, ctrl->node_key_id, sizeof(ctrl->node_key_id));
  ESP_LOGI(TAG, "tailscale identity %s machine=%s node=%s", ctrl->identity_status, ctrl->machine_key_id,
           ctrl->node_key_id);
}

static void copy_preview(char *dest, size_t dest_size, const char *src, size_t src_len) {
  if (dest_size == 0) return;
  dest[0] = '\0';
  if (src == nullptr || src_len == 0) return;

  static const char hex[] = "0123456789ABCDEF";
  size_t out = 0;
  size_t limit = src_len < 96 ? src_len : 96;
  for (size_t index = 0; index < limit && out + 1 < dest_size; index++) {
    unsigned char ch = (unsigned char) src[index];
    if (ch >= 0x20 && ch <= 0x7E && ch != '\\') {
      dest[out++] = (char) ch;
      continue;
    }
    if (out + 4 >= dest_size) break;
    dest[out++] = '\\';
    dest[out++] = 'x';
    dest[out++] = hex[(ch >> 4) & 0x0F];
    dest[out++] = hex[ch & 0x0F];
  }
  dest[out] = '\0';
}

static const char *extract_map_json_payload(char *buffer, size_t *buffer_len) {
  if (buffer == nullptr || buffer_len == nullptr || *buffer_len == 0) return buffer;
  if (*buffer_len >= 4) {
    uint32_t msg_len = ((uint32_t) (uint8_t) buffer[0]) | (((uint32_t) (uint8_t) buffer[1]) << 8) |
                       (((uint32_t) (uint8_t) buffer[2]) << 16) | (((uint32_t) (uint8_t) buffer[3]) << 24);
    if (msg_len > 0 && msg_len <= *buffer_len - 4 && buffer[4] == '{') {
      memmove(buffer, buffer + 4, msg_len);
      *buffer_len = msg_len;
      buffer[msg_len] = '\0';
      return buffer;
    }
  }
  return buffer;
}

static bool load_persisted_identity(ts_ctrl_t *ctrl, char *source_out, size_t source_out_size) {
  const char *reason = nullptr;
  nvs_handle_t handle = 0;
  esp_err_t err = nvs_open(IDENTITY_PREF_NAMESPACE, NVS_READONLY, &handle);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    snprintf(source_out, source_out_size, "%s", "no_ns");
    ESP_LOGW(TAG, "tailscale identity namespace not found");
    return false;
  }
  if (err != ESP_OK) {
    snprintf(source_out, source_out_size, "%s", "nvs_open_fail");
    ESP_LOGW(TAG, "failed to open tailscale identity namespace (%s)", esp_err_to_name(err));
    return false;
  }

  saved_identity_t saved{};
  size_t blob_size = sizeof(saved);
  err = nvs_get_blob(handle, IDENTITY_PREF_KEY, &saved, &blob_size);
  nvs_close(handle);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    snprintf(source_out, source_out_size, "%s", "no_blob");
    ESP_LOGW(TAG, "tailscale identity blob not found");
    return false;
  }
  if (err != ESP_OK) {
    snprintf(source_out, source_out_size, "%s", "load_fail");
    ESP_LOGW(TAG, "failed to load tailscale identity blob (%s)", esp_err_to_name(err));
    return false;
  }
  if (blob_size != sizeof(saved)) {
    snprintf(source_out, source_out_size, "%s", "bad_size");
    ESP_LOGW(TAG, "tailscale identity blob has unexpected size (%u)", (unsigned) blob_size);
    return false;
  }

  if (!is_saved_identity_valid(saved, &reason)) {
    snprintf(source_out, source_out_size, "%s", reason != nullptr ? reason : "invalid");
    ESP_LOGW(TAG, "tailscale identity in NVS is invalid (%s)", reason != nullptr ? reason : "invalid");
    return false;
  }

  apply_saved_identity(ctrl, saved);
  snprintf(source_out, source_out_size, "%s", "nvs");
  ESP_LOGI(TAG, "loaded tailscale identity from NVS");
  return true;
}

static void save_persisted_identity(ts_ctrl_t *ctrl, char *result_out, size_t result_out_size) {
  saved_identity_t saved{};
  saved.magic = IDENTITY_PREF_MAGIC;
  memcpy(saved.machine_key_private, ctrl->machine_key_private, sizeof(saved.machine_key_private));
  memcpy(saved.node_key_private, ctrl->node_key_private, sizeof(saved.node_key_private));
  memcpy(saved.disco_key_private, ctrl->disco_key_private, sizeof(saved.disco_key_private));

  nvs_handle_t handle = 0;
  esp_err_t err = nvs_open(IDENTITY_PREF_NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) {
    snprintf(result_out, result_out_size, "%s", "nvs_open_fail");
    ESP_LOGW(TAG, "failed to open tailscale identity namespace for write (%s)", esp_err_to_name(err));
    return;
  }

  err = nvs_set_blob(handle, IDENTITY_PREF_KEY, &saved, sizeof(saved));
  if (err != ESP_OK) {
    nvs_close(handle);
    snprintf(result_out, result_out_size, "%s", "save_fail");
    ESP_LOGW(TAG, "failed to write tailscale identity blob (%s)", esp_err_to_name(err));
    return;
  }

  err = nvs_commit(handle);
  nvs_close(handle);
  if (err != ESP_OK) {
    snprintf(result_out, result_out_size, "%s", "sync_fail");
    ESP_LOGW(TAG, "failed to commit tailscale identity blob (%s)", esp_err_to_name(err));
    return;
  }
  snprintf(result_out, result_out_size, "%s", "nvs_saved");
  ESP_LOGI(TAG, "persisted tailscale identity to NVS");
}

static void set_socket_timeout(int sock, int timeout_ms) {
  if (sock < 0 || timeout_ms < 0) return;
  struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int tls_bio_send(void *ctx, const unsigned char *buf, size_t len) {
  int sock = *(int *) ctx;
  int written = write(sock, buf, len);
  if (written >= 0) return written;
  if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
  if (errno == EPIPE || errno == ECONNRESET) return MBEDTLS_ERR_NET_CONN_RESET;
  return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int tls_bio_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout_ms) {
  int sock = *(int *) ctx;
  set_socket_timeout(sock, timeout_ms > 0 ? (int) timeout_ms : 5000);
  int received = read(sock, buf, len);
  if (received >= 0) return received;
  if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_TIMEOUT;
  if (errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
  if (errno == EPIPE || errno == ECONNRESET) return MBEDTLS_ERR_NET_CONN_RESET;
  return MBEDTLS_ERR_NET_RECV_FAILED;
}

static esp_err_t write_all(ts_ctrl_t *ctrl, const uint8_t *data, size_t len) {
  while (len > 0) {
    int written = 0;
    if (ctrl->tls_active) {
      written = mbedtls_ssl_write(&ctrl->ssl, data, len);
      if (written == MBEDTLS_ERR_SSL_WANT_READ || written == MBEDTLS_ERR_SSL_WANT_WRITE ||
          written == MBEDTLS_ERR_SSL_TIMEOUT) {
        vTaskDelay(pdMS_TO_TICKS(10));
        continue;
      }
    } else {
      written = write(ctrl->sock, data, len);
    }
    if (written <= 0) {
      ESP_LOGE(TAG, "write failed (%d, errno=%d)", written, errno);
      return ESP_FAIL;
    }
    data += written;
    len -= (size_t) written;
  }
  return ESP_OK;
}

static esp_err_t read_all(ts_ctrl_t *ctrl, uint8_t *data, size_t len, int timeout_ms) {
  int64_t deadline_us = timeout_ms >= 0 ? esp_timer_get_time() + ((int64_t) timeout_ms * 1000) : -1;
  while (len > 0) {
    int received = 0;
    if (ctrl->tls_active) {
      received = mbedtls_ssl_read(&ctrl->ssl, data, len);
      if (received == MBEDTLS_ERR_SSL_WANT_READ || received == MBEDTLS_ERR_SSL_WANT_WRITE ||
          received == MBEDTLS_ERR_SSL_TIMEOUT) {
        if (deadline_us >= 0 && esp_timer_get_time() >= deadline_us) return ESP_ERR_TIMEOUT;
        vTaskDelay(pdMS_TO_TICKS(10));
        continue;
      }
    } else {
      set_socket_timeout(ctrl->sock, timeout_ms);
      received = read(ctrl->sock, data, len);
    }
    if (received <= 0) {
      return ESP_ERR_TIMEOUT;
    }
    data += received;
    len -= (size_t) received;
  }
  return ESP_OK;
}

static int recv_some(ts_ctrl_t *ctrl, uint8_t *data, size_t len, int timeout_ms) {
  if (ctrl->tls_active) {
    int64_t deadline_us = timeout_ms >= 0 ? esp_timer_get_time() + ((int64_t) timeout_ms * 1000) : -1;
    while (true) {
      int received = mbedtls_ssl_read(&ctrl->ssl, data, len);
      if (received == MBEDTLS_ERR_SSL_WANT_READ || received == MBEDTLS_ERR_SSL_WANT_WRITE ||
          received == MBEDTLS_ERR_SSL_TIMEOUT) {
        if (deadline_us >= 0 && esp_timer_get_time() >= deadline_us) return -1;
        vTaskDelay(pdMS_TO_TICKS(10));
        continue;
      }
      return received;
    }
  }
  set_socket_timeout(ctrl->sock, timeout_ms);
  return read(ctrl->sock, data, len);
}

static void bytes_to_hex(const uint8_t *input, size_t len, char *output) {
  static const char hex[] = "0123456789abcdef";
  for (size_t index = 0; index < len; index++) {
    output[index * 2] = hex[(input[index] >> 4) & 0x0F];
    output[index * 2 + 1] = hex[input[index] & 0x0F];
  }
  output[len * 2] = '\0';
}

static int hex_value(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
  if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
  return -1;
}

static bool hex_to_bytes(const char *hex, uint8_t *output, size_t len) {
  for (size_t index = 0; index < len; index++) {
    int hi = hex_value(hex[index * 2]);
    int lo = hex_value(hex[index * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    output[index] = (uint8_t) ((hi << 4) | lo);
  }
  return true;
}

static void b64enc(const uint8_t *input, size_t input_len, char *output) {
  size_t written = 0;
  if (mbedtls_base64_encode((unsigned char *) output, 256, &written, input, input_len) != 0) {
    output[0] = '\0';
    return;
  }
  output[written] = '\0';
}

static void json_escape(char *out, size_t out_size, const char *input) {
  size_t out_pos = 0;
  for (size_t index = 0; input[index] != '\0' && out_pos + 1 < out_size; index++) {
    unsigned char ch = (unsigned char) input[index];
    if (ch == '"' || ch == '\\') {
      if (out_pos + 2 >= out_size) break;
      out[out_pos++] = '\\';
      out[out_pos++] = (char) ch;
      continue;
    }
    if (ch < 0x20) continue;
    out[out_pos++] = (char) ch;
  }
  out[out_pos] = '\0';
}

static void build_hostinfo(ts_ctrl_t *ctrl) {
  char escaped_name[128];
  char services_part[160] = "";
  char ingress_part[64] = "";
  json_escape(escaped_name, sizeof(escaped_name), ctrl->machine_name);
  if (ctrl->advertised_service_port != 0) {
    snprintf(services_part, sizeof(services_part),
             ",\"Services\":[{\"Proto\":\"tcp\",\"Port\":%u,\"Description\":\"esp32-service\"}]",
             (unsigned) ctrl->advertised_service_port);
  }
  if (ctrl->ingress_enabled) {
    snprintf(ingress_part, sizeof(ingress_part), ",\"IngressEnabled\":true");
  } else if (ctrl->wire_ingress) {
    snprintf(ingress_part, sizeof(ingress_part), ",\"WireIngress\":true");
  }
  snprintf(ctrl->hostinfo, sizeof(ctrl->hostinfo),
           "{\"Hostname\":\"%s\",\"OS\":\"linux\",\"OSVersion\":\"ESP-IDF\",\"GoArch\":\"arm\","
           "\"Userspace\":true%s%s,\"NetInfo\":{\"PreferredDERP\":%u}}",
           escaped_name, ingress_part, services_part, (unsigned) DEFAULT_DERP_REGION);
}

static void build_node_key_string(const uint8_t *public_key, char *out, size_t out_size) {
  char key_hex[65];
  bytes_to_hex(public_key, 32, key_hex);
  snprintf(out, out_size, "nodekey:%s", key_hex);
}

static void build_disco_key_string(const uint8_t *public_key, char *out, size_t out_size) {
  char key_hex[65];
  bytes_to_hex(public_key, 32, key_hex);
  snprintf(out, out_size, "discokey:%s", key_hex);
}

static bool build_challenge_response_string(ts_ctrl_t *ctrl, char *out, size_t out_size) {
  if (!ctrl->has_node_key_challenge) return false;

  uint8_t challenge_pub[32];
  uint8_t response[32];
  char response_hex[65];

  memcpy(challenge_pub, ctrl->node_key_challenge, sizeof(challenge_pub));
  challenge_pub[31] &= 0x7F;
  noise_x25519(response, ctrl->node_key_private, challenge_pub);
  bytes_to_hex(response, sizeof(response), response_hex);
  snprintf(out, out_size, "chalresp:%s", response_hex);
  return true;
}

static const uint8_t *find_token(const uint8_t *data, size_t len, const char *token) {
  size_t token_len = strlen(token);
  if (token_len == 0 || len < token_len) return nullptr;
  for (size_t index = 0; index + token_len <= len; index++) {
    if (memcmp(data + index, token, token_len) == 0) return data + index;
  }
  return nullptr;
}

static uint8_t *find_http_header_end(uint8_t *data, size_t len) {
  if (len < 4) return nullptr;
  for (size_t index = 0; index + 4 <= len; index++) {
    if (memcmp(data + index, "\r\n\r\n", 4) == 0) return data + index;
  }
  return nullptr;
}

static void trim_cidr_suffix(char *address) {
  char *slash = strchr(address, '/');
  if (slash != nullptr) *slash = '\0';
}

static bool json_extract_first_array_string(const char *json, const char *key, char *out, size_t out_size) {
  const char *key_pos = strstr(json, key);
  if (key_pos == nullptr) return false;
  const char *array_pos = strchr(key_pos, '[');
  if (array_pos == nullptr) return false;
  const char *value_start = strchr(array_pos, '"');
  if (value_start == nullptr) return false;
  value_start++;
  const char *value_end = strchr(value_start, '"');
  if (value_end == nullptr || value_end <= value_start) return false;

  size_t copy_len = (size_t) (value_end - value_start);
  if (copy_len >= out_size) copy_len = out_size - 1;
  memcpy(out, value_start, copy_len);
  out[copy_len] = '\0';
  return true;
}

static bool json_extract_string_value(const char *json, const char *key, char *out, size_t out_size) {
  const char *key_pos = strstr(json, key);
  if (key_pos == nullptr) return false;
  const char *colon = strchr(key_pos, ':');
  if (colon == nullptr) return false;
  const char *value_start = strchr(colon, '"');
  if (value_start == nullptr) return false;
  value_start++;
  const char *value_end = strchr(value_start, '"');
  if (value_end == nullptr || value_end <= value_start) return false;

  size_t copy_len = (size_t) (value_end - value_start);
  if (copy_len >= out_size) copy_len = out_size - 1;
  memcpy(out, value_start, copy_len);
  out[copy_len] = '\0';
  return true;
}

static int json_count_array_objects(const char *json, const char *key) {
  const char *key_pos = strstr(json, key);
  if (key_pos == nullptr) return -1;
  const char *cursor = strchr(key_pos, '[');
  if (cursor == nullptr) return -1;
  cursor++;

  bool in_string = false;
  bool escaped = false;
  int object_depth = 0;
  int nested_array_depth = 0;
  int count = 0;

  while (*cursor != '\0') {
    char ch = *cursor++;
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        in_string = false;
      }
      continue;
    }

    if (ch == '"') {
      in_string = true;
      continue;
    }
    if (ch == '{') {
      if (object_depth == 0 && nested_array_depth == 0) count++;
      object_depth++;
      continue;
    }
    if (ch == '}') {
      if (object_depth > 0) object_depth--;
      continue;
    }
    if (ch == '[') {
      if (object_depth > 0) nested_array_depth++;
      continue;
    }
    if (ch == ']') {
      if (object_depth == 0 && nested_array_depth == 0) return count;
      if (nested_array_depth > 0) nested_array_depth--;
    }
  }

  return count;
}

static void update_diagnostics_from_json(ts_ctrl_t *ctrl, const char *json, bool replace_peer_count) {
  char address[64];
  const char *node_pos = strstr(json, "\"Node\"");
  if (node_pos != nullptr) {
    if (json_extract_first_array_string(node_pos, "\"Addresses\"", address, sizeof(address))) {
      trim_cidr_suffix(address);
      if (address[0] != '\0') {
        snprintf(ctrl->vpn_ip, sizeof(ctrl->vpn_ip), "%s", address);
      }
    }
  } else if (json_extract_string_value(json, "\"SelfNodeV4MasqAddrForThisPeer\"", address, sizeof(address))) {
    if (address[0] != '\0') {
      snprintf(ctrl->vpn_ip, sizeof(ctrl->vpn_ip), "%s", address);
    }
  }

  int peers = json_count_array_objects(json, "\"Peers\"");
  if (peers >= 0 && replace_peer_count) {
    ctrl->peer_count = peers;
  }
}

static esp_err_t noise_send(ts_ctrl_t *ctrl, const uint8_t *plaintext, size_t plaintext_len) {
  size_t ciphertext_len = plaintext_len + NOISE_MAC_LEN;
  uint8_t *frame = (uint8_t *) malloc(3 + ciphertext_len);
  if (frame == nullptr) return ESP_ERR_NO_MEM;

  frame[0] = 0x04;
  frame[1] = (ciphertext_len >> 8) & 0xFF;
  frame[2] = ciphertext_len & 0xFF;

  esp_err_t status =
      noise_encrypt(ctrl->noise.tx_key, ctrl->noise.tx_nonce, nullptr, 0, plaintext, plaintext_len, frame + 3);
  if (status == ESP_OK) {
    ctrl->noise.tx_nonce++;
    status = write_all(ctrl, frame, 3 + ciphertext_len);
  }

  free(frame);
  return status;
}

static int noise_recv_plain(ts_ctrl_t *ctrl, uint8_t *plaintext, size_t plaintext_cap, int timeout_ms) {
  uint8_t header[3];
  if (read_all(ctrl, header, sizeof(header), timeout_ms) != ESP_OK) return -1;
  if (header[0] != 0x04) {
    ESP_LOGE(TAG, "unexpected noise transport type 0x%02x", header[0]);
    return -1;
  }

  uint16_t ciphertext_len = ((uint16_t) header[1] << 8) | header[2];
  if (ciphertext_len < NOISE_MAC_LEN) return -1;

  size_t plaintext_len = (size_t) ciphertext_len - NOISE_MAC_LEN;
  if (plaintext_len > plaintext_cap) {
    ESP_LOGE(TAG, "noise frame too large (%u > %u)", (unsigned) plaintext_len, (unsigned) plaintext_cap);
    return -1;
  }

  uint8_t *ciphertext = (uint8_t *) malloc(ciphertext_len);
  if (ciphertext == nullptr) return -1;
  if (read_all(ctrl, ciphertext, ciphertext_len, timeout_ms) != ESP_OK) {
    free(ciphertext);
    return -1;
  }

  esp_err_t status =
      noise_decrypt(ctrl->noise.rx_key, ctrl->noise.rx_nonce, nullptr, 0, ciphertext, ciphertext_len, plaintext);
  free(ciphertext);
  if (status != ESP_OK) {
    ESP_LOGE(TAG, "noise decrypt failed");
    return -1;
  }

  ctrl->noise.rx_nonce++;
  return (int) plaintext_len;
}

static void process_proactive_frames(ts_ctrl_t *ctrl, const uint8_t *extra_data, size_t extra_len) {
  uint8_t combined[TSC_PROACTIVE_MAX];
  size_t combined_len = 0;
  size_t offset = 0;
  uint64_t nonce = 0;
  int frame_count = 0;

  ctrl->has_node_key_challenge = false;

  while (offset + 3 <= extra_len) {
    uint8_t frame_type = extra_data[offset];
    uint16_t frame_len = ((uint16_t) extra_data[offset + 1] << 8) | extra_data[offset + 2];
    if (offset + 3 + frame_len > extra_len) break;

    if (frame_type == 0x04 && frame_len >= NOISE_MAC_LEN) {
      size_t plaintext_len = (size_t) frame_len - NOISE_MAC_LEN;
      uint8_t plaintext[256];
      if (plaintext_len <= sizeof(plaintext) &&
          noise_decrypt(ctrl->noise.rx_key, nonce, nullptr, 0, extra_data + offset + 3, frame_len, plaintext) ==
              ESP_OK) {
        size_t copy_len = plaintext_len;
        if (copy_len > sizeof(combined) - combined_len) copy_len = sizeof(combined) - combined_len;
        if (copy_len > 0) {
          memcpy(combined + combined_len, plaintext, copy_len);
          combined_len += copy_len;
        }
      }
    }

    nonce++;
    frame_count++;
    offset += 3 + frame_len;
  }

  const uint8_t *challenge = find_token(combined, combined_len, "chalpub:");
  if (challenge != nullptr && challenge + 8 + 64 <= combined + combined_len) {
    if (hex_to_bytes((const char *) challenge + 8, ctrl->node_key_challenge, sizeof(ctrl->node_key_challenge))) {
      ctrl->has_node_key_challenge = true;
      ESP_LOGI(TAG, "nodeKeyChallenge captured from EarlyNoise");
    }
  }

  ctrl->noise.rx_nonce = frame_count;
}

static esp_err_t h2_recv_frame(ts_ctrl_t *ctrl, uint8_t *frame_buf, size_t frame_buf_cap, h2_frame_t *frame,
                               int timeout_ms) {
  while (true) {
    size_t available = ctrl->h2_pending_len - ctrl->h2_pending_off;
    if (available >= H2_FRAME_HEADER_LEN) {
      h2_parse_header(ctrl->h2_pending + ctrl->h2_pending_off, frame);
      size_t total_len = H2_FRAME_HEADER_LEN + frame->len;
      if (total_len > frame_buf_cap) return ESP_ERR_INVALID_SIZE;
      if (available >= total_len) {
        memcpy(frame_buf, ctrl->h2_pending + ctrl->h2_pending_off, total_len);
        ctrl->h2_pending_off += total_len;
        if (ctrl->h2_pending_off == ctrl->h2_pending_len) {
          ctrl->h2_pending_off = 0;
          ctrl->h2_pending_len = 0;
        }
        return ESP_OK;
      }
    }

    if (ctrl->h2_pending_off > 0 && available > 0) {
      memmove(ctrl->h2_pending, ctrl->h2_pending + ctrl->h2_pending_off, available);
    }
    ctrl->h2_pending_off = 0;
    ctrl->h2_pending_len = available;

    int received = noise_recv_plain(ctrl, ctrl->h2_pending + ctrl->h2_pending_len,
                                    sizeof(ctrl->h2_pending) - ctrl->h2_pending_len, timeout_ms);
    if (received < 0) {
      ESP_LOGD(TAG, "no Noise transport payload available for H2 frame within timeout");
      return ESP_ERR_TIMEOUT;
    }
    ctrl->h2_pending_len += (size_t) received;
  }
}

static esp_err_t send_h2_control_response(ts_ctrl_t *ctrl, const uint8_t *frame_buf, const h2_frame_t *frame) {
  uint8_t out[32];
  int out_len = -1;

  if (frame->type == H2_PING && !(frame->flags & H2_ACK)) {
    out_len = h2_build_ping_frame(out, sizeof(out), frame_buf + H2_FRAME_HEADER_LEN, 1);
  } else if (frame->type == H2_SETTINGS && !(frame->flags & H2_ACK)) {
    out_len = h2_build_settings_ack(out, sizeof(out));
  }

  if (out_len > 0) return noise_send(ctrl, out, (size_t) out_len);
  return ESP_OK;
}

static esp_err_t send_h2_window_update(ts_ctrl_t *ctrl, uint32_t stream_id, uint32_t increment) {
  if (increment == 0) return ESP_OK;

  uint8_t buf[32];
  int pos = 0;
  int frame_len = h2_build_window_update(buf + pos, sizeof(buf) - pos, 0, increment);
  if (frame_len < 0) return ESP_FAIL;
  pos += frame_len;

  if (stream_id != 0) {
    frame_len = h2_build_window_update(buf + pos, sizeof(buf) - pos, stream_id, increment);
    if (frame_len < 0) return ESP_FAIL;
    pos += frame_len;
  }

  return noise_send(ctrl, buf, (size_t) pos);
}

static esp_err_t send_h2_request(ts_ctrl_t *ctrl, uint32_t stream_id, const char *path, const char *body) {
  size_t body_len = strlen(body);
  size_t h2_cap = body_len + 512;
  uint8_t *h2_buf = (uint8_t *) malloc(h2_cap);
  if (h2_buf == nullptr) return ESP_ERR_NO_MEM;

  int pos = 0;
  int frame_len = h2_build_headers_frame(h2_buf + pos, h2_cap - pos, "POST", path, H2_SCHEME, SERVER_HOST,
                                         "application/json", nullptr, nullptr, stream_id, 0);
  if (frame_len < 0) {
    ESP_LOGE(TAG, "failed to build H2 headers for %s stream=%u body_len=%u", path, (unsigned) stream_id,
             (unsigned) body_len);
    free(h2_buf);
    return ESP_FAIL;
  }
  pos += frame_len;

  frame_len = h2_build_data_frame(h2_buf + pos, h2_cap - pos, (const uint8_t *) body, (uint32_t) body_len, stream_id,
                                  1);
  if (frame_len < 0) {
    ESP_LOGE(TAG, "failed to build H2 data for %s stream=%u body_len=%u", path, (unsigned) stream_id,
             (unsigned) body_len);
    free(h2_buf);
    return ESP_FAIL;
  }
  pos += frame_len;

  esp_err_t status = noise_send(ctrl, h2_buf, (size_t) pos);
  if (status != ESP_OK) {
    ESP_LOGE(TAG, "failed to send H2 request for %s stream=%u status=%d body_len=%u", path, (unsigned) stream_id,
             (int) status, (unsigned) body_len);
  }
  free(h2_buf);
  return status;
}

static esp_err_t read_h2_response(ts_ctrl_t *ctrl, uint32_t stream_id, char *json_out, size_t json_out_size,
                                  size_t *json_len_out, int timeout_ms) {
  uint8_t *frame_buf = (uint8_t *) malloc(TSC_FRAME_BUF);
  if (frame_buf == nullptr) return ESP_ERR_NO_MEM;

  size_t json_len = 0;
  bool saw_stream = false;

  while (true) {
    h2_frame_t frame{};
    esp_err_t status = h2_recv_frame(ctrl, frame_buf, TSC_FRAME_BUF, &frame, timeout_ms);
    if (status != ESP_OK) {
      ESP_LOGE(TAG, "H2 response read timed out for stream %u", (unsigned) stream_id);
      free(frame_buf);
      return status;
    }

    if (frame.type == H2_GOAWAY) {
      uint32_t last_stream = 0;
      uint32_t error_code = 0;
      if (frame.len >= 8) {
        h2_parse_goaway(frame_buf + H2_FRAME_HEADER_LEN, frame.len, &last_stream, &error_code);
      }
      int debug_len = frame.len > 8 ? (int) (frame.len - 8) : 0;
      if (debug_len > 48) debug_len = 48;
      ESP_LOGE(TAG, "server sent GOAWAY while waiting for stream %u (last_stream=%u error=%u debug=%.48s)",
               (unsigned) stream_id, (unsigned) last_stream, (unsigned) error_code,
               debug_len > 0 ? (const char *) (frame_buf + H2_FRAME_HEADER_LEN + 8) : "");
      free(frame_buf);
      return ESP_FAIL;
    }

    status = send_h2_control_response(ctrl, frame_buf, &frame);
    if (status != ESP_OK) {
      free(frame_buf);
      return status;
    }

    if (frame.stream_id != stream_id) continue;
    saw_stream = true;
    ESP_LOGE(TAG, "stream %u frame type=%u flags=0x%02x len=%u", (unsigned) stream_id, frame.type, frame.flags,
             (unsigned) frame.len);

    if (frame.type == H2_DATA && frame.len > 0) {
      size_t available = json_out_size - 1 - json_len;
      size_t copy_len = frame.len < available ? frame.len : available;
      memcpy(json_out + json_len, frame_buf + H2_FRAME_HEADER_LEN, copy_len);
      json_len += copy_len;
      json_out[json_len] = '\0';

      status = send_h2_window_update(ctrl, stream_id, frame.len);
      if (status != ESP_OK) {
        free(frame_buf);
        return status;
      }
    }

    if (frame.flags & H2_END_STREAM) {
      if (json_len_out != nullptr) *json_len_out = json_len;
      free(frame_buf);
      return saw_stream ? ESP_OK : ESP_FAIL;
    }
  }
}

static esp_err_t build_register_body(ts_ctrl_t *ctrl, char *body, size_t body_size) {
  char node_key[80];
  char auth_part[320] = "";
  char challenge_part[128] = "";

  build_node_key_string(ctrl->node_key_public, node_key, sizeof(node_key));

  if (ctrl->auth_key[0] != '\0') {
    char escaped_auth[256];
    json_escape(escaped_auth, sizeof(escaped_auth), ctrl->auth_key);
    snprintf(auth_part, sizeof(auth_part), ",\"Auth\":{\"AuthKey\":\"%s\"}", escaped_auth);
  }

  char challenge_response[96];
  if (build_challenge_response_string(ctrl, challenge_response, sizeof(challenge_response))) {
    snprintf(challenge_part, sizeof(challenge_part), ",\"NodeKeyChallengeResponse\":\"%s\"", challenge_response);
  }

  int written = snprintf(body, body_size, "{\"Version\":%d,\"NodeKey\":\"%s\"%s,\"Hostinfo\":%s%s}",
                         NOISE_PROTOCOL_VER, node_key, auth_part, ctrl->hostinfo, challenge_part);
  return (written > 0 && (size_t) written < body_size) ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static esp_err_t build_map_body(ts_ctrl_t *ctrl, char *body, size_t body_size, bool streaming, bool omit_peers) {
  char node_key[80];
  char disco_key[80];
  build_node_key_string(ctrl->node_key_public, node_key, sizeof(node_key));
  build_disco_key_string(ctrl->disco_key_public, disco_key, sizeof(disco_key));

  int written = snprintf(body, body_size,
                         "{\"Version\":%d,\"KeepAlive\":true,\"NodeKey\":\"%s\",\"DiscoKey\":\"%s\","
                         "\"Hostinfo\":%s,\"Stream\":%s,\"Compress\":\"\",\"OmitPeers\":%s}",
                         NOISE_PROTOCOL_VER, node_key, disco_key, ctrl->hostinfo, streaming ? "true" : "false",
                         omit_peers ? "true" : "false");
  return (written > 0 && (size_t) written < body_size) ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static esp_err_t send_h2_preface(ts_ctrl_t *ctrl) {
  uint8_t buf[128];
  int pos = 0;

  int frame_len = h2_build_preface(buf + pos, sizeof(buf) - pos);
  if (frame_len < 0) return ESP_FAIL;
  pos += frame_len;

  uint32_t conn_window_delta = H2_CLIENT_INITIAL_WINDOW_SIZE - H2_DEFAULT_WINDOW_SIZE;
  if (conn_window_delta > 0) {
    frame_len = h2_build_window_update(buf + pos, sizeof(buf) - pos, 0, conn_window_delta);
    if (frame_len < 0) return ESP_FAIL;
    pos += frame_len;
  }

  esp_err_t status = noise_send(ctrl, buf, (size_t) pos);
  if (status != ESP_OK) return status;

  ctrl->h2_pending_len = 0;
  ctrl->h2_pending_off = 0;
  int received = noise_recv_plain(ctrl, ctrl->h2_pending, sizeof(ctrl->h2_pending), 1000);
  if (received > 0) {
    ctrl->h2_pending_len = (size_t) received;
    ctrl->h2_pending_off = 0;
  }
  return ESP_OK;
}

}  // namespace

esp_err_t ts_ctrl_init(ts_ctrl_t *ctrl, const char *auth_key, const char *hostname, bool wire_ingress,
                       bool ingress_enabled, uint16_t advertised_service_port) {
  memset(ctrl, 0, sizeof(*ctrl));
  ctrl->sock = -1;
  ctrl->tls_active = false;
  mbedtls_ssl_init(&ctrl->ssl);
  mbedtls_ssl_config_init(&ctrl->ssl_conf);
  mbedtls_entropy_init(&ctrl->entropy);
  mbedtls_ctr_drbg_init(&ctrl->ctr_drbg);
  ctrl->stream_map_once = 3;
  ctrl->stream_map_live = 5;
  ctrl->identity_loaded_from_storage = false;
  ctrl->wire_ingress = wire_ingress;
  ctrl->ingress_enabled = ingress_enabled;
  ctrl->advertised_service_port = advertised_service_port;
  snprintf(ctrl->auth_key, sizeof(ctrl->auth_key), "%s", auth_key != nullptr ? auth_key : "");
  snprintf(ctrl->machine_name, sizeof(ctrl->machine_name), "%s", hostname != nullptr ? hostname : "");
  snprintf(ctrl->vpn_ip, sizeof(ctrl->vpn_ip), "0.0.0.0");
  snprintf(ctrl->identity_status, sizeof(ctrl->identity_status), "%s", "unknown");
  ctrl->machine_key_id[0] = '\0';
  ctrl->node_key_id[0] = '\0';
  ctrl->last_register_preview[0] = '\0';
  ctrl->last_map_preview[0] = '\0';
  build_hostinfo(ctrl);
  return ESP_OK;
}

esp_err_t ts_ctrl_connect(ts_ctrl_t *ctrl) {
  ctrl->sock = socket(AF_INET, SOCK_STREAM, 0);
  if (ctrl->sock < 0) {
    ESP_LOGE(TAG, "socket creation failed");
    return ESP_FAIL;
  }

  struct hostent *host = gethostbyname(SERVER_HOST);
  if (host == nullptr || host->h_addr_list == nullptr || host->h_addr_list[0] == nullptr) {
    ESP_LOGE(TAG, "DNS resolve failed for %s", SERVER_HOST);
    ts_ctrl_close(ctrl);
    return ESP_FAIL;
  }

  struct sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_port = htons(SERVER_PORT);
  memcpy(&address.sin_addr, host->h_addr_list[0], host->h_length);

  if (connect(ctrl->sock, (struct sockaddr *) &address, sizeof(address)) != 0) {
    ESP_LOGE(TAG, "connect failed for %s:%u", SERVER_HOST, SERVER_PORT);
    ts_ctrl_close(ctrl);
    return ESP_FAIL;
  }

  if (mbedtls_ctr_drbg_seed(&ctrl->ctr_drbg, mbedtls_entropy_func, &ctrl->entropy, nullptr, 0) != 0) {
    ESP_LOGE(TAG, "TLS RNG seed failed");
    ts_ctrl_close(ctrl);
    return ESP_FAIL;
  }
  if (mbedtls_ssl_config_defaults(&ctrl->ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    ESP_LOGE(TAG, "TLS config defaults failed");
    ts_ctrl_close(ctrl);
    return ESP_FAIL;
  }
  mbedtls_ssl_conf_authmode(&ctrl->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&ctrl->ssl_conf, mbedtls_ctr_drbg_random, &ctrl->ctr_drbg);
  mbedtls_ssl_conf_read_timeout(&ctrl->ssl_conf, 5000);

  if (mbedtls_ssl_setup(&ctrl->ssl, &ctrl->ssl_conf) != 0) {
    ESP_LOGE(TAG, "TLS setup failed");
    ts_ctrl_close(ctrl);
    return ESP_FAIL;
  }
  if (mbedtls_ssl_set_hostname(&ctrl->ssl, SERVER_HOST) != 0) {
    ESP_LOGE(TAG, "TLS hostname setup failed");
    ts_ctrl_close(ctrl);
    return ESP_FAIL;
  }

  mbedtls_ssl_set_bio(&ctrl->ssl, &ctrl->sock, tls_bio_send, nullptr, tls_bio_recv_timeout);
  while (true) {
    int ret = mbedtls_ssl_handshake(&ctrl->ssl);
    if (ret == 0) break;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_TIMEOUT) {
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }
    char err_buf[128];
    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    ESP_LOGE(TAG, "TLS handshake failed: %s", err_buf);
    ts_ctrl_close(ctrl);
    return ESP_FAIL;
  }
  ctrl->tls_active = true;
  return ESP_OK;
}

esp_err_t ts_ctrl_handshake(ts_ctrl_t *ctrl) {
  ESP_LOGI(TAG, "starting tailscale control handshake");
  char identity_source[32];
  if (load_persisted_identity(ctrl, identity_source, sizeof(identity_source))) {
    ctrl->identity_loaded_from_storage = true;
    char identity_status[64];
    snprintf(identity_status, sizeof(identity_status), "loaded_%s", identity_source);
    update_identity_debug(ctrl, identity_status);
  } else {
    ctrl->identity_loaded_from_storage = false;
    esp_fill_random(ctrl->machine_key_private, sizeof(ctrl->machine_key_private));
    esp_fill_random(ctrl->node_key_private, sizeof(ctrl->node_key_private));
    esp_fill_random(ctrl->disco_key_private, sizeof(ctrl->disco_key_private));
    derive_public_keys(ctrl);
    char save_result[32];
    save_persisted_identity(ctrl, save_result, sizeof(save_result));
    char identity_status[64];
    snprintf(identity_status, sizeof(identity_status), "generated_%s_%s", identity_source, save_result);
    update_identity_debug(ctrl, identity_status);
  }
  noise_ik_init(&ctrl->noise, ctrl->machine_key_private, ctrl->machine_key_public);

  uint8_t msg1[160];
  size_t msg1_len = 0;
  if (noise_ik_write_msg1(&ctrl->noise, msg1, &msg1_len) != ESP_OK) return ESP_FAIL;

  char msg1_b64[256];
  b64enc(msg1, msg1_len, msg1_b64);
  size_t msg1_b64_len = strlen(msg1_b64);

  char request[1024];
  int request_len = snprintf(request, sizeof(request),
                             "POST /ts2021 HTTP/1.1\r\n"
                             "Host: %s\r\n"
                             "Upgrade: tailscale-control-protocol\r\n"
                             "Connection: Upgrade\r\n"
                             "User-Agent: Tailscale\r\n"
                             "X-Tailscale-Handshake: %s\r\n"
                             "Content-Length: 0\r\n"
                             "\r\n",
                             SERVER_HOST, msg1_b64);
  if (request_len <= 0 || (size_t) request_len >= sizeof(request)) return ESP_ERR_INVALID_SIZE;
  if (write_all(ctrl, (const uint8_t *) request, (size_t) request_len) != ESP_OK) {
    ESP_LOGE(TAG, "failed to send HTTP upgrade request");
    return ESP_FAIL;
  }
  ESP_LOGI(TAG, "upgrade request sent (%d bytes)", request_len);

  uint8_t *response = (uint8_t *) malloc(TSC_HTTP_BUF);
  if (response == nullptr) return ESP_ERR_NO_MEM;
  int total = 0;
  uint8_t *header_end = nullptr;
  while (total < TSC_HTTP_BUF - 1 && header_end == nullptr) {
    int received = recv_some(ctrl, response + total, (size_t) (TSC_HTTP_BUF - 1 - total), 5000);
    if (received <= 0) break;
    total += received;
    header_end = find_http_header_end(response, (size_t) total);
  }

  if (total <= 0) {
    ESP_LOGE(TAG, "timeout waiting for HTTP upgrade response");
    free(response);
    return ESP_ERR_TIMEOUT;
  }
  response[total] = '\0';
  ESP_LOGI(TAG, "upgrade response received (%d bytes)", total);

  if (strstr((const char *) response, "101") == nullptr) {
    ESP_LOGE(TAG, "control plane rejected Noise upgrade: %.160s", response);
    free(response);
    return ESP_FAIL;
  }

  uint8_t *body_start = header_end;
  if (body_start == nullptr) {
    ESP_LOGE(TAG, "HTTP upgrade response missing header terminator");
    free(response);
    return ESP_FAIL;
  }
  body_start += 4;

  int body_len = total - (int) (body_start - response);
  ESP_LOGI(TAG, "HTTP upgrade accepted, body bytes buffered=%d", body_len);
  uint8_t *body_buf = nullptr;
  int body_buf_len = 0;
  if (body_len > 0) {
    body_buf = (uint8_t *) malloc((size_t) body_len + 1024);
    if (body_buf == nullptr) {
      free(response);
      return ESP_ERR_NO_MEM;
    }
    memcpy(body_buf, body_start, (size_t) body_len);
    body_buf_len = body_len;
  }
  if (body_buf_len < 3) {
    if (body_buf == nullptr) {
      body_buf = (uint8_t *) malloc(1024);
      if (body_buf == nullptr) return ESP_ERR_NO_MEM;
    }
    if (read_all(ctrl, body_buf + body_buf_len, (size_t) (3 - body_buf_len), 5000) != ESP_OK) {
      ESP_LOGE(TAG,
               "timeout waiting for Noise msg2 header (msg1=%u bytes b64=%u req=%d resp=%d buffered_body=%d errno=%d)",
               (unsigned) msg1_len, (unsigned) msg1_b64_len, request_len, total, body_len, errno);
      ESP_LOGE(TAG, "upgrade response snapshot: %.200s", response);
      free(body_buf);
      free(response);
      return ESP_ERR_TIMEOUT;
    }
    body_buf_len = 3;
  }
  free(response);

  uint8_t msg_type = body_buf[0];
  uint16_t payload_len = ((uint16_t) body_buf[1] << 8) | body_buf[2];
  ESP_LOGI(TAG, "Noise msg2 header: type=0x%02x payload=%u", msg_type, payload_len);
  if (msg_type != 0x02) {
    ESP_LOGE(TAG, "unexpected Noise msg2 type 0x%02x", msg_type);
    free(body_buf);
    return ESP_FAIL;
  }

  int msg2_total = 3 + payload_len;
  if (body_buf_len < msg2_total) {
    uint8_t *grown = (uint8_t *) realloc(body_buf, (size_t) msg2_total + 1024);
    if (grown == nullptr) {
      free(body_buf);
      return ESP_ERR_NO_MEM;
    }
    body_buf = grown;
    if (read_all(ctrl, body_buf + body_buf_len, (size_t) (msg2_total - body_buf_len), 10000) != ESP_OK) {
      ESP_LOGE(TAG, "timeout waiting for full Noise msg2 payload");
      free(body_buf);
      return ESP_ERR_TIMEOUT;
    }
    body_buf_len = msg2_total;
  }

  if (noise_ik_read_msg2(&ctrl->noise, body_buf + 3, payload_len) != ESP_OK) {
    ESP_LOGE(TAG, "Noise msg2 authentication failed");
    free(body_buf);
    return ESP_ERR_INVALID_MAC;
  }
  ESP_LOGI(TAG, "Noise transport keys derived");

  int extra_len = body_buf_len - msg2_total;
  uint8_t *extra_data = nullptr;
  if (extra_len > 0) {
    extra_data = (uint8_t *) malloc((size_t) extra_len);
    if (extra_data != nullptr) memcpy(extra_data, body_buf + msg2_total, (size_t) extra_len);
  } else {
    extra_data = (uint8_t *) malloc(TSC_PROACTIVE_MAX);
    if (extra_data != nullptr) {
      int received = recv_some(ctrl, extra_data, TSC_PROACTIVE_MAX, 2000);
      if (received > 0) {
        extra_len = received;
      } else {
        free(extra_data);
        extra_data = nullptr;
      }
    }
  }
  free(body_buf);

  if (extra_data != nullptr && extra_len > 0) {
    ESP_LOGI(TAG, "processing %d bytes of proactive server data", extra_len);
    process_proactive_frames(ctrl, extra_data, (size_t) extra_len);
    free(extra_data);
  }

  ESP_LOGI(TAG, "sending HTTP/2 preface");
  return send_h2_preface(ctrl);
}

esp_err_t ts_ctrl_register(ts_ctrl_t *ctrl) {
  char body[1536];
  if (build_register_body(ctrl, body, sizeof(body)) != ESP_OK) return ESP_FAIL;
  if (send_h2_request(ctrl, 1, "/machine/register", body) != ESP_OK) {
    ESP_LOGE(TAG, "failed to send /machine/register request");
    return ESP_FAIL;
  }

  char response[8192];
  size_t response_len = 0;
  response[0] = '\0';
  esp_err_t status = read_h2_response(ctrl, 1, response, sizeof(response), &response_len, 10000);
  if (status != ESP_OK) {
    ESP_LOGE(TAG, "/machine/register response failed with status=%d", (int) status);
    return status;
  }

  if (response_len > 0) {
    copy_preview(ctrl->last_register_preview, sizeof(ctrl->last_register_preview), response, response_len);
    update_diagnostics_from_json(ctrl, response, false);
    bool has_auth_url = strstr(response, "\"AuthURL\":\"") != nullptr;
    bool machine_authorized = strstr(response, "\"MachineAuthorized\":true") != nullptr;
    bool node_key_expired = strstr(response, "\"NodeKeyExpired\":true") != nullptr;
    bool has_error = strstr(response, "\"Error\":\"") != nullptr;
    ESP_LOGE(TAG,
             "/machine/register response bytes=%u vpn_ip=%s auth_url=%d machine_authorized=%d node_key_expired=%d error=%d",
             (unsigned) response_len, ctrl->vpn_ip, has_auth_url, machine_authorized, node_key_expired, has_error);
    if (has_error) {
      const char *error_pos = strstr(response, "\"Error\":\"");
      ESP_LOGW(TAG, "/machine/register error snippet=%.160s", error_pos != nullptr ? error_pos : response);
    }
  }
  return ESP_OK;
}

esp_err_t ts_ctrl_fetch_map(ts_ctrl_t *ctrl) {
  char body[1536];
  if (build_map_body(ctrl, body, sizeof(body), false, false) != ESP_OK) return ESP_FAIL;
  ESP_LOGE(TAG, "requesting one-shot /machine/map stream=%u", (unsigned) ctrl->stream_map_once);
  if (send_h2_request(ctrl, ctrl->stream_map_once, "/machine/map", body) != ESP_OK) {
    ESP_LOGE(TAG, "one-shot /machine/map send failed");
    return ESP_FAIL;
  }

  char *response = (char *) malloc(TSC_RESP_MAX + 1);
  if (response == nullptr) {
    ESP_LOGE(TAG, "failed to allocate map response buffer (%u bytes)", (unsigned) (TSC_RESP_MAX + 1));
    return ESP_ERR_NO_MEM;
  }
  response[0] = '\0';

  size_t response_len = 0;
  ESP_LOGE(TAG, "waiting for one-shot /machine/map response");
  esp_err_t status = read_h2_response(ctrl, ctrl->stream_map_once, response, TSC_RESP_MAX + 1, &response_len, 15000);
  if (status == ESP_OK && response_len > 0) {
    const char *payload = extract_map_json_payload(response, &response_len);
    copy_preview(ctrl->last_map_preview, sizeof(ctrl->last_map_preview), payload, response_len);
    update_diagnostics_from_json(ctrl, payload, true);
    ESP_LOGI(TAG, "/machine/map response bytes=%u vpn_ip=%s peers=%d", (unsigned) response_len, ctrl->vpn_ip,
             ctrl->peer_count);
    ESP_LOGI(TAG, "/machine/map snippet=%.320s", payload);
  } else if (status != ESP_OK) {
    copy_preview(ctrl->last_map_preview, sizeof(ctrl->last_map_preview), response, response_len);
    ESP_LOGE(TAG, "/machine/map failed status=%d bytes=%u partial=%.200s", (int) status, (unsigned) response_len,
             response);
  }

  free(response);
  return status;
}

esp_err_t ts_ctrl_start_stream(ts_ctrl_t *ctrl) {
  char body[1536];
  if (build_map_body(ctrl, body, sizeof(body), true, true) != ESP_OK) return ESP_FAIL;
  ESP_LOGE(TAG, "requesting streaming /machine/map stream=%u", (unsigned) ctrl->stream_map_live);
  return send_h2_request(ctrl, ctrl->stream_map_live, "/machine/map", body);
}

int ts_ctrl_poll_stream(ts_ctrl_t *ctrl, int timeout_ms) {
  uint8_t *frame_buf = (uint8_t *) malloc(TSC_FRAME_BUF);
  if (frame_buf == nullptr) return -1;

  h2_frame_t frame{};
  esp_err_t status = h2_recv_frame(ctrl, frame_buf, TSC_FRAME_BUF, &frame, timeout_ms);
  if (status != ESP_OK) {
    free(frame_buf);
    return status == ESP_ERR_TIMEOUT ? 0 : -1;
  }

  if (frame.type == H2_GOAWAY) {
    free(frame_buf);
    return -1;
  }

  status = send_h2_control_response(ctrl, frame_buf, &frame);
  if (status != ESP_OK) {
    free(frame_buf);
    return -1;
  }

  if (frame.type == H2_DATA && frame.stream_id == ctrl->stream_map_live && frame.len > 0) {
    char *json = (char *) malloc(frame.len + 1);
    if (json == nullptr) {
      free(frame_buf);
      return -1;
    }
    memcpy(json, frame_buf + H2_FRAME_HEADER_LEN, frame.len);
    json[frame.len] = '\0';
    update_diagnostics_from_json(ctrl, json, true);
    free(json);

    status = send_h2_window_update(ctrl, ctrl->stream_map_live, frame.len);
    free(frame_buf);
    return status == ESP_OK ? 1 : -1;
  }

  if ((frame.flags & H2_END_STREAM) && frame.stream_id == ctrl->stream_map_live) {
    free(frame_buf);
    return -1;
  }

  free(frame_buf);
  return 1;
}

void ts_ctrl_close(ts_ctrl_t *ctrl) {
  if (ctrl->tls_active) {
    mbedtls_ssl_close_notify(&ctrl->ssl);
  }
  mbedtls_ssl_free(&ctrl->ssl);
  mbedtls_ssl_config_free(&ctrl->ssl_conf);
  mbedtls_ctr_drbg_free(&ctrl->ctr_drbg);
  mbedtls_entropy_free(&ctrl->entropy);
  mbedtls_ssl_init(&ctrl->ssl);
  mbedtls_ssl_config_init(&ctrl->ssl_conf);
  mbedtls_ctr_drbg_init(&ctrl->ctr_drbg);
  mbedtls_entropy_init(&ctrl->entropy);
  ctrl->tls_active = false;
  if (ctrl->sock >= 0) {
    close(ctrl->sock);
    ctrl->sock = -1;
  }
  ctrl->h2_pending_len = 0;
  ctrl->h2_pending_off = 0;
}
