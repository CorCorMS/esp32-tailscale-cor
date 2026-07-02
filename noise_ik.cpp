// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: LicenseRef-NonCommercial
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#include "noise_ik.h"
#include "blake2s.h"
#include "esp_random.h"
#include "esp_log.h"
#include "mbedtls/chachapoly.h"
extern "C" {
#include "x25519.h"
}
#include <string.h>
#include <stdio.h>

static const char *TAG = "ts_noise";

/* Tailscale ts2021 Noise public key from /key publicKey (not legacyPublicKey). */
static const uint8_t SERVER_KEY[32] = {
    0x7d,0x27,0x92,0xf9,0xc9,0x8d,0x75,0x3d,0x20,0x42,0x47,0x15,
    0x36,0x80,0x19,0x49,0x10,0x4c,0x24,0x7f,0x95,0xea,0xc7,0x70,
    0xf8,0xfb,0x32,0x15,0x95,0xe2,0x17,0x3b
};

static const char NOISE_PROTO_NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

void noise_ik_generate_keypair(uint8_t *priv, uint8_t *pub) {
    (void) x25519_base(pub, priv, 1);
}

void noise_x25519(uint8_t *out, const uint8_t *priv, const uint8_t *pub) {
    (void) x25519(out, priv, pub, 1);
}

/* Blake2s hash helper */
static void hash(uint8_t o[32], const uint8_t *d, size_t l) {
    blake2s(o, 32, NULL, 0, d, l);
}

static void hmac(uint8_t o[32], const uint8_t *k, size_t kl, const uint8_t *d, size_t dl) {
    uint8_t kb[64]; memset(kb, 0, 64);
    if (kl > 64) { hash(kb, k, kl); kl = 32; } else memcpy(kb, k, kl);
    for (int i = 0; i < 64; i++) kb[i] ^= 0x36;
    blake2s_ctx c; uint8_t in[32];
    blake2s_init(&c, 32, NULL, 0); blake2s_update(&c, kb, 64); blake2s_update(&c, d, dl); blake2s_final(&c, in);
    for (int i = 0; i < 64; i++) kb[i] ^= 0x36 ^ 0x5c;
    blake2s_init(&c, 32, NULL, 0); blake2s_update(&c, kb, 64); blake2s_update(&c, in, 32); blake2s_final(&c, o);
}

static void hkdf(const uint8_t *ck, const uint8_t *in, size_t il, uint8_t *o1, uint8_t *o2) {
    uint8_t tk[32], c = 1; hmac(tk, ck, 32, in, il);
    hmac(o1, tk, 32, &c, 1); c++;
    if (o2) { uint8_t b[33]; memcpy(b, o1, 32); b[32] = c; hmac(o2, tk, 32, b, 33); }
}

static void mx_h(uint8_t h[32], const uint8_t *d, size_t l) {
    blake2s_ctx c; blake2s_init(&c, 32, NULL, 0); blake2s_update(&c, h, 32); blake2s_update(&c, d, l); blake2s_final(&c, h);
}

static void mx_k(uint8_t ck[32], uint8_t k[32], const uint8_t *dh) {
    hkdf(ck, dh, 32, ck, k);
}

static int cp_aead(uint8_t *ct, const uint8_t *key, uint64_t nonce,
                   const uint8_t *ad, size_t al, const uint8_t *pt, size_t pl) {
    uint8_t n[12]; memset(n, 0, 4);
    for (int i = 0; i < 8; i++) n[11 - i] = (nonce >> (i * 8)) & 0xFF;
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    mbedtls_chachapoly_setkey(&ctx, key);
    uint8_t dummy; const uint8_t *in = pt ? pt : &dummy;
    int r = mbedtls_chachapoly_encrypt_and_tag(&ctx, pl, n, ad, al, in, ct, ct + pl);
    mbedtls_chachapoly_free(&ctx);
    return r;
}

static int cp_ad(uint8_t *pt, const uint8_t *key, uint64_t nonce,
                 const uint8_t *ad, size_t al, const uint8_t *ct, size_t cl) {
    if (cl < 16) return -1;
    size_t pl = cl - 16;
    uint8_t n[12]; memset(n, 0, 4);
    for (int i = 0; i < 8; i++) n[11 - i] = (nonce >> (i * 8)) & 0xFF;
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    mbedtls_chachapoly_setkey(&ctx, key);
    uint8_t dummy; uint8_t *out = pt ? pt : &dummy;
    int r = mbedtls_chachapoly_auth_decrypt(&ctx, pl, n, ad, al, ct + pl, ct, out);
    mbedtls_chachapoly_free(&ctx);
    return r;
}

void noise_ik_init(noise_ik_t *st, const uint8_t *lp, const uint8_t *lq) {
    memset(st, 0, sizeof(*st));
    memcpy(st->local_static_private, lp, 32);
    memcpy(st->local_static_public, lq, 32);
    memcpy(st->remote_static_public, SERVER_KEY, 32);
    hash(st->h, (const uint8_t *)NOISE_PROTO_NAME, strlen(NOISE_PROTO_NAME));
    memcpy(st->ck, st->h, 32);
    char pl[64]; int plen = snprintf(pl, sizeof(pl), "Tailscale Control Protocol v%d", NOISE_PROTOCOL_VER);
    mx_h(st->h, (const uint8_t *)pl, plen);
    mx_h(st->h, st->remote_static_public, 32);
    esp_fill_random(st->local_ephemeral_private, 32);
    st->local_ephemeral_private[0] &= 248;
    st->local_ephemeral_private[31] &= 127;
    st->local_ephemeral_private[31] |= 64;
    noise_ik_generate_keypair(st->local_ephemeral_private, st->local_ephemeral_public);
    st->handshake_complete = false;
}

esp_err_t noise_ik_write_msg1(noise_ik_t *st, uint8_t *out, size_t *out_len) {
    size_t p = 0;
    out[p++] = (NOISE_PROTOCOL_VER >> 8) & 0xFF;
    out[p++] = NOISE_PROTOCOL_VER & 0xFF;
    out[p++] = 0x01; out[p++] = 0x00; out[p++] = 0x60;
    memcpy(out + p, st->local_ephemeral_public, 32);
    mx_h(st->h, st->local_ephemeral_public, 32); p += 32;
    uint8_t dh[32], k[32];
    (void) x25519(dh, st->local_ephemeral_private, st->remote_static_public, 1);
    mx_k(st->ck, k, dh);
    cp_aead(out + p, k, 0, st->h, 32, st->local_static_public, 32);
    mx_h(st->h, out + p, 48); p += 48;
    (void) x25519(dh, st->local_static_private, st->remote_static_public, 1);
    mx_k(st->ck, k, dh);
    cp_aead(out + p, k, 0, st->h, 32, NULL, 0);
    mx_h(st->h, out + p, 16); p += 16;
    *out_len = p; return ESP_OK;
}

esp_err_t noise_ik_read_msg2(noise_ik_t *st, const uint8_t *msg, size_t len) {
    if (len < 48) return ESP_ERR_INVALID_SIZE;
    size_t o = 0; uint8_t re[32], dh[32], k[32];
    memcpy(re, msg, 32); mx_h(st->h, re, 32); o += 32;
    (void) x25519(dh, st->local_ephemeral_private, re, 1); mx_k(st->ck, k, dh);
    (void) x25519(dh, st->local_static_private, re, 1); mx_k(st->ck, k, dh);
    size_t ct_len = len - o;
    if (cp_ad(NULL, k, 0, st->h, 32, msg + o, ct_len)) return ESP_ERR_INVALID_MAC;
    mx_h(st->h, msg + o, ct_len);
    hkdf(st->ck, NULL, 0, st->tx_key, st->rx_key);
    st->tx_nonce = 0; st->rx_nonce = 0; st->handshake_complete = true;
    return ESP_OK;
}

esp_err_t noise_encrypt(const uint8_t *key, uint64_t nonce,
                        const uint8_t *ad, size_t al, const uint8_t *pt, size_t pl, uint8_t *ct) {
    return cp_aead(ct, key, nonce, ad, al, pt, pl) ? ESP_FAIL : ESP_OK;
}

esp_err_t noise_decrypt(const uint8_t *key, uint64_t nonce,
                        const uint8_t *ad, size_t al, const uint8_t *ct, size_t cl, uint8_t *pt) {
    return cp_ad(pt, key, nonce, ad, al, ct, cl) ? ESP_ERR_INVALID_MAC : ESP_OK;
}
