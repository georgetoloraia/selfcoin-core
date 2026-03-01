#pragma once

#include <cstdint>
#include <optional>

#include "common/types.hpp"

namespace selfcoin::p2p {

struct Frame {
  std::uint16_t msg_type{0};
  Bytes payload;
};

enum class FrameReadError {
  NONE = 0,
  IO_EOF,
  TIMEOUT_HEADER,
  TIMEOUT_BODY,
  INVALID_HEADER,
  INVALID_LENGTH,
  INVALID_CHECKSUM,
};

Bytes encode_frame(const Frame& f, std::uint32_t magic = MAGIC, std::uint16_t proto_version = PROTOCOL_VERSION);
std::optional<Frame> decode_frame(const Bytes& b, std::size_t max_payload_len = 8 * 1024 * 1024,
                                  std::uint32_t magic = MAGIC, std::uint16_t proto_version = PROTOCOL_VERSION);

bool read_exact(int fd, std::uint8_t* dst, std::size_t n);
bool write_all(int fd, const std::uint8_t* src, std::size_t n);
std::optional<Frame> read_frame_fd(int fd, std::size_t max_payload_len = 8 * 1024 * 1024,
                                   std::uint32_t magic = MAGIC, std::uint16_t proto_version = PROTOCOL_VERSION);
std::optional<Frame> read_frame_fd_timed(int fd, std::size_t max_payload_len, std::uint32_t expected_magic,
                                         std::uint16_t expected_proto_version, std::uint32_t header_timeout_ms,
                                         std::uint32_t body_timeout_ms, FrameReadError* err);
bool write_frame_fd(int fd, const Frame& f, std::uint32_t magic = MAGIC, std::uint16_t proto_version = PROTOCOL_VERSION);

}  // namespace selfcoin::p2p
