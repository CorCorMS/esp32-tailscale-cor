// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: Apache-2.0
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#define NOISE_PROTOCOL_VER 131
#define NOISE_KEY_LEN 32
#define NOISE_HASH_LEN 32
#define NOISE_MAC_LEN 16

typedef struct {
    uint8_t h[NOISE_HASH_LEN];
    uint8_t ck[NOISE_HASH_LEN];
    uint8_t local_static_private[32];
    uint8_t local_static_public[32];
    uint8_t local_ephemeral_private[32];
    uint8_t local_ephemeral_public[32];
    uint8_t remote_static_public[32];
    uint8_t tx_key[NOISE_KEY_LEN];
    uint8_t rx_key[NOISE_KEY_LEN];
    uint64_t tx_nonce;
    uint64_t rx_nonce;
    bool handshake_complete;
} noise_ik_t;

void noise_ik_init(noise_ik_t *state, const uint8_t *local_priv, const uint8_t *local_pub);
esp_err_t noise_ik_write_msg1(noise_ik_t *state, uint8_t *out, size_t *out_len);
esp_err_t noise_ik_read_msg2(noise_ik_t *state, const uint8_t *msg, size_t len);
esp_err_t noise_encrypt(const uint8_t *key, uint64_t nonce, const uint8_t *ad, size_t ad_len, const uint8_t *pt, size_t pt_len, uint8_t *ct);
esp_err_t noise_decrypt(const uint8_t *key, uint64_t nonce, const uint8_t *ad, size_t ad_len, const uint8_t *ct, size_t ct_len, uint8_t *pt);
void noise_ik_generate_keypair(uint8_t *priv, uint8_t *pub);
void noise_x25519(uint8_t *out, const uint8_t *priv, const uint8_t *pub);
