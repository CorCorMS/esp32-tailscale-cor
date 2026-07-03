// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: Apache-2.0
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#pragma once
#include <stdint.h>
#include <stddef.h>

#define H2_FRAME_HEADER_LEN 9
#define H2_DEFAULT_WINDOW_SIZE 65535U
#define H2_CLIENT_INITIAL_WINDOW_SIZE (256U * 1024U)

typedef struct { uint32_t len; uint8_t type; uint8_t flags; uint32_t stream_id; } h2_frame_t;

enum h2_type { H2_DATA=0, H2_HEADERS=1, H2_PRIORITY=2, H2_RST_STREAM=3, H2_SETTINGS=4, H2_PUSH_PROMISE=5, H2_PING=6, H2_GOAWAY=7, H2_WINDOW_UPDATE=8 };
enum h2_flags { H2_ACK=0x01, H2_END_STREAM=0x01, H2_END_HEADERS=0x04, H2_PADDED=0x08, H2_PRIORITY_BIT=0x20 };
enum h2_settings_id { H2_SETTINGS_HEADER_TABLE_SIZE=1, H2_SETTINGS_ENABLE_PUSH=2, H2_SETTINGS_MAX_CONCURRENT_STREAMS=3, H2_SETTINGS_INITIAL_WINDOW_SIZE=4, H2_SETTINGS_MAX_FRAME_SIZE=5, H2_SETTINGS_MAX_HEADER_LIST_SIZE=6 };

int h2_build_preface(uint8_t *out, size_t out_size);
int h2_build_settings_ack(uint8_t *out, size_t out_size);
int h2_build_headers_frame(uint8_t *out, size_t out_size, const char *method, const char *path, const char *scheme,
                           const char *authority, const char *content_type, const char *extra_header_name,
                           const char *extra_header_value, uint32_t stream_id, int end_stream);
int h2_build_data_frame(uint8_t *out, size_t out_size, const uint8_t *data, uint32_t data_len, uint32_t stream_id, int end_stream);
int h2_build_ping_frame(uint8_t *out, size_t out_size, const uint8_t *opaque, int ack);
int h2_build_window_update(uint8_t *out, size_t out_size, uint32_t stream_id, uint32_t increment);
int h2_parse_header(const uint8_t *data, h2_frame_t *frame);
int h2_parse_settings(const uint8_t *data, uint32_t len, uint32_t *initial_window_size);
int h2_parse_goaway(const uint8_t *data, uint32_t len, uint32_t *last_stream, uint32_t *error_code);
