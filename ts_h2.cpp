// SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
// SPDX-License-Identifier: LicenseRef-NonCommercial
//
// See LICENSE for full license text.
// Third-party code in this directory may have separate licensing.
//
#include "ts_h2.h"

#include <string.h>

namespace {

static void pack24(uint8_t *out, uint32_t value) {
  out[0] = (value >> 16) & 0xFF;
  out[1] = (value >> 8) & 0xFF;
  out[2] = value & 0xFF;
}

static int write_frame_header(uint8_t *out, uint32_t len, uint8_t type, uint8_t flags, uint32_t stream_id) {
  pack24(out, len);
  out[3] = type;
  out[4] = flags;
  out[5] = (stream_id >> 24) & 0x7F;
  out[6] = (stream_id >> 16) & 0xFF;
  out[7] = (stream_id >> 8) & 0xFF;
  out[8] = stream_id & 0xFF;
  return H2_FRAME_HEADER_LEN;
}

static int hpack_indexed(uint8_t *out, size_t out_size, uint8_t index) {
  if (out_size < 1) return -1;
  out[0] = 0x80 | index;
  return 1;
}

static int hpack_literal_indexed(uint8_t *out, size_t out_size, uint8_t name_index, const char *value) {
  size_t value_len = strlen(value);
  if (out_size < value_len + 2) return -1;
  out[0] = 0x40 | (name_index & 0x3F);
  out[1] = (uint8_t) value_len;
  memcpy(out + 2, value, value_len);
  return (int) (value_len + 2);
}

}  // namespace

int h2_build_preface(uint8_t *out, size_t out_size) {
  if (out_size < 24 + H2_FRAME_HEADER_LEN + 6) return -1;

  int pos = 0;
  memcpy(out + pos, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
  pos += 24;

  pos += write_frame_header(out + pos, 6, H2_SETTINGS, 0, 0);
  out[pos++] = 0x00;
  out[pos++] = H2_SETTINGS_INITIAL_WINDOW_SIZE;
  out[pos++] = (H2_CLIENT_INITIAL_WINDOW_SIZE >> 24) & 0xFF;
  out[pos++] = (H2_CLIENT_INITIAL_WINDOW_SIZE >> 16) & 0xFF;
  out[pos++] = (H2_CLIENT_INITIAL_WINDOW_SIZE >> 8) & 0xFF;
  out[pos++] = H2_CLIENT_INITIAL_WINDOW_SIZE & 0xFF;

  return pos;
}

int h2_build_settings_ack(uint8_t *out, size_t out_size) {
  if (out_size < H2_FRAME_HEADER_LEN) return -1;
  return write_frame_header(out, 0, H2_SETTINGS, H2_ACK, 0);
}

int h2_build_headers_frame(uint8_t *out, size_t out_size, const char *method, const char *path, const char *scheme,
                           const char *authority, const char *content_type, uint32_t stream_id, int end_stream) {
  uint8_t hpack[256];
  int hpack_len = 0;
  int written = 0;

  if (strcmp(method, "POST") == 0) {
    written = hpack_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 3);
  } else if (strcmp(method, "GET") == 0) {
    written = hpack_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 2);
  } else {
    written = hpack_literal_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 2, method);
  }
  if (written < 0) return -1;
  hpack_len += written;

  if (strcmp(path, "/") == 0) {
    written = hpack_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 4);
  } else {
    written = hpack_literal_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 4, path);
  }
  if (written < 0) return -1;
  hpack_len += written;

  if (scheme == nullptr || strcmp(scheme, "http") == 0) {
    written = hpack_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 6);
  } else if (strcmp(scheme, "https") == 0) {
    written = hpack_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 7);
  } else {
    written = hpack_literal_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 6, scheme);
  }
  if (written < 0) return -1;
  hpack_len += written;

  if (authority && authority[0]) {
    written = hpack_literal_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 1, authority);
    if (written < 0) return -1;
    hpack_len += written;
  }

  if (content_type && content_type[0]) {
    written = hpack_literal_indexed(hpack + hpack_len, sizeof(hpack) - hpack_len, 31, content_type);
    if (written < 0) return -1;
    hpack_len += written;
  }

  if (out_size < (size_t) H2_FRAME_HEADER_LEN + (size_t) hpack_len) return -1;

  uint8_t flags = H2_END_HEADERS;
  if (end_stream) flags |= H2_END_STREAM;
  write_frame_header(out, (uint32_t) hpack_len, H2_HEADERS, flags, stream_id);
  memcpy(out + H2_FRAME_HEADER_LEN, hpack, (size_t) hpack_len);
  return H2_FRAME_HEADER_LEN + hpack_len;
}

int h2_build_data_frame(uint8_t *out, size_t out_size, const uint8_t *data, uint32_t data_len,
                        uint32_t stream_id, int end_stream) {
  if (out_size < (size_t) H2_FRAME_HEADER_LEN + data_len) return -1;
  write_frame_header(out, data_len, H2_DATA, end_stream ? H2_END_STREAM : 0, stream_id);
  if (data_len > 0 && data != nullptr) memcpy(out + H2_FRAME_HEADER_LEN, data, data_len);
  return H2_FRAME_HEADER_LEN + (int) data_len;
}

int h2_build_ping_frame(uint8_t *out, size_t out_size, const uint8_t *opaque, int ack) {
  if (out_size < H2_FRAME_HEADER_LEN + 8) return -1;
  write_frame_header(out, 8, H2_PING, ack ? H2_ACK : 0, 0);
  memcpy(out + H2_FRAME_HEADER_LEN, opaque, 8);
  return H2_FRAME_HEADER_LEN + 8;
}

int h2_build_window_update(uint8_t *out, size_t out_size, uint32_t stream_id, uint32_t increment) {
  if (out_size < H2_FRAME_HEADER_LEN + 4) return -1;
  write_frame_header(out, 4, H2_WINDOW_UPDATE, 0, stream_id);
  out[9] = (increment >> 24) & 0x7F;
  out[10] = (increment >> 16) & 0xFF;
  out[11] = (increment >> 8) & 0xFF;
  out[12] = increment & 0xFF;
  return H2_FRAME_HEADER_LEN + 4;
}

int h2_parse_header(const uint8_t *data, h2_frame_t *frame) {
  frame->len = ((uint32_t) data[0] << 16) | ((uint32_t) data[1] << 8) | data[2];
  frame->type = data[3];
  frame->flags = data[4];
  frame->stream_id =
      (((uint32_t) data[5] & 0x7F) << 24) | ((uint32_t) data[6] << 16) | ((uint32_t) data[7] << 8) | data[8];
  return 0;
}

int h2_parse_settings(const uint8_t *data, uint32_t len, uint32_t *initial_window_size) {
  for (uint32_t offset = 0; offset + 6 <= len; offset += 6) {
    uint16_t id = ((uint16_t) data[offset] << 8) | data[offset + 1];
    uint32_t value = ((uint32_t) data[offset + 2] << 24) | ((uint32_t) data[offset + 3] << 16) |
                     ((uint32_t) data[offset + 4] << 8) | data[offset + 5];
    if (id == H2_SETTINGS_INITIAL_WINDOW_SIZE && initial_window_size != nullptr) {
      *initial_window_size = value;
    }
  }
  return 0;
}

int h2_parse_goaway(const uint8_t *data, uint32_t len, uint32_t *last_stream, uint32_t *error_code) {
  if (len < 8) return -1;
  if (last_stream != nullptr) {
    *last_stream = (((uint32_t) data[0] & 0x7F) << 24) | ((uint32_t) data[1] << 16) |
                   ((uint32_t) data[2] << 8) | data[3];
  }
  if (error_code != nullptr) {
    *error_code = ((uint32_t) data[4] << 24) | ((uint32_t) data[5] << 16) | ((uint32_t) data[6] << 8) | data[7];
  }
  return 0;
}
