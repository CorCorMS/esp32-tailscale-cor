// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: LicenseRef-NonCommercial
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#pragma once

#include <stddef.h>
#include <stdint.h>

#define BLAKE2S_BLOCK_SIZE 64

typedef struct {
    uint8_t b[64];
    uint32_t h[8];
    uint32_t t[2];
    size_t c;
    size_t outlen;
} blake2s_ctx;

int blake2s_init(blake2s_ctx *ctx, size_t outlen, const void *key, size_t keylen);
void blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen);
void blake2s_final(blake2s_ctx *ctx, void *out);
int blake2s(void *out, size_t outlen, const void *key, size_t keylen, const void *in, size_t inlen);
