// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: Apache-2.0
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl.h"
#include "noise_ik.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int sock;
    int socket_rcv_timeout_ms;
    bool tls_active;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config ssl_conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    noise_ik_t noise;
    uint8_t machine_key_private[32];
    uint8_t machine_key_public[32];
    uint8_t node_key_private[32];
    uint8_t node_key_public[32];
    uint8_t disco_key_private[32];
    uint8_t disco_key_public[32];
    uint8_t node_key_challenge[32];
    bool has_node_key_challenge;
    bool identity_loaded_from_storage;
    bool wire_ingress;
    bool ingress_enabled;
    char auth_key[128];
    char machine_name[64];
    char hostinfo[512];
    char vpn_ip[64];
    char identity_status[64];
    char machine_key_id[24];
    char node_key_id[24];
    char last_register_preview[256];
    char last_map_preview[384];
    uint16_t advertised_service_port;
    int peer_count;
    uint8_t h2_pending[32 * 1024];
    size_t h2_pending_len;
    size_t h2_pending_off;
    uint32_t stream_map_once;
    uint32_t stream_map_live;
} ts_ctrl_t;

esp_err_t ts_ctrl_init(ts_ctrl_t *c, const char *auth_key, const char *hostname, bool wire_ingress,
                       bool ingress_enabled, uint16_t advertised_service_port);
esp_err_t ts_ctrl_connect(ts_ctrl_t *c);
esp_err_t ts_ctrl_handshake(ts_ctrl_t *c);
esp_err_t ts_ctrl_register(ts_ctrl_t *c);
esp_err_t ts_ctrl_fetch_map(ts_ctrl_t *c);
esp_err_t ts_ctrl_start_stream(ts_ctrl_t *c);
int ts_ctrl_poll_stream(ts_ctrl_t *c, int tmo_ms);
void ts_ctrl_close(ts_ctrl_t *c);

#ifdef __cplusplus
}
#endif
