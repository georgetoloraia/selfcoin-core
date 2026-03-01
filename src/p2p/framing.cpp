#include "p2p/framing.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace selfcoin::p2p {

Bytes encode_frame(const Frame& f, std::uint32_t magic, std::uint16_t proto_version) {
  codec::ByteWriter w;
  w.u32le(magic);
  w.u16le(proto_version);
  w.u16le(f.msg_type);
  w.u32le(static_cast<std::uint32_t>(f.payload.size()));
  w.bytes(f.payload);
  const Hash32 chk = crypto::sha256d(f.payload);
  w.bytes_fixed(chk);
  return w.take();
}

std::optional<Frame> decode_frame(const Bytes& b, std::size_t max_payload_len, std::uint32_t expected_magic,
                                  std::uint16_t expected_proto_version) {
  Frame f;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto magic = r.u32le();
        auto version = r.u16le();
        auto msg_type = r.u16le();
        auto payload_len = r.u32le();
        if (!magic || !version || !msg_type || !payload_len) return false;
        if (*magic != expected_magic || *version != expected_proto_version) return false;
        if (*payload_len > max_payload_len) return false;
        auto payload = r.bytes(*payload_len);
        auto checksum = r.bytes_fixed<32>();
        if (!payload || !checksum) return false;
        if (crypto::sha256d(*payload) != *checksum) return false;
        f.msg_type = *msg_type;
        f.payload = *payload;
        return true;
      })) {
    return std::nullopt;
  }
  return f;
}

bool read_exact(int fd, std::uint8_t* dst, std::size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t k = ::recv(fd, dst + off, n - off, 0);
    if (k <= 0) return false;
    off += static_cast<size_t>(k);
  }
  return true;
}

bool write_all(int fd, const std::uint8_t* src, std::size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t k = ::send(fd, src + off, n - off, 0);
    if (k <= 0) return false;
    off += static_cast<size_t>(k);
  }
  return true;
}

namespace {

bool wait_readable(int fd, std::uint32_t timeout_ms) {
  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;
  const int r = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
  if (r <= 0) return false;
  return (pfd.revents & POLLIN) != 0;
}

bool read_exact_timed(int fd, std::uint8_t* dst, std::size_t n, std::uint32_t timeout_ms) {
  const auto start = std::chrono::steady_clock::now();
  std::size_t off = 0;
  while (off < n) {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
    if (elapsed >= static_cast<long long>(timeout_ms)) return false;
    const std::uint32_t remain = static_cast<std::uint32_t>(timeout_ms - elapsed);
    if (!wait_readable(fd, remain)) return false;
    const ssize_t k = ::recv(fd, dst + off, n - off, 0);
    if (k <= 0) return false;
    off += static_cast<std::size_t>(k);
  }
  return true;
}

}  // namespace

std::optional<Frame> read_frame_fd(int fd, std::size_t max_payload_len, std::uint32_t expected_magic,
                                   std::uint16_t expected_proto_version) {
  return read_frame_fd_timed(fd, max_payload_len, expected_magic, expected_proto_version, 120000, 3000, nullptr);
}

std::optional<Frame> read_frame_fd_timed(int fd, std::size_t max_payload_len, std::uint32_t expected_magic,
                                         std::uint16_t expected_proto_version, std::uint32_t header_timeout_ms,
                                         std::uint32_t body_timeout_ms, FrameReadError* err) {
  if (err) *err = FrameReadError::NONE;
  std::array<std::uint8_t, 12> hdr{};
  if (!read_exact_timed(fd, hdr.data(), hdr.size(), header_timeout_ms)) {
    if (err) *err = FrameReadError::TIMEOUT_HEADER;
    return std::nullopt;
  }

  codec::ByteReader r(Bytes(hdr.begin(), hdr.end()));
  auto magic = r.u32le();
  auto version = r.u16le();
  auto msg = r.u16le();
  auto len = r.u32le();
  if (!magic || !version || !msg || !len) {
    if (err) *err = FrameReadError::INVALID_HEADER;
    return std::nullopt;
  }
  if (*magic != expected_magic || *version != expected_proto_version) {
    if (err) *err = FrameReadError::INVALID_HEADER;
    return std::nullopt;
  }
  if (*len > max_payload_len) {
    if (err) *err = FrameReadError::INVALID_LENGTH;
    return std::nullopt;
  }

  Bytes payload(*len);
  if (*len > 0 && !read_exact_timed(fd, payload.data(), payload.size(), body_timeout_ms)) {
    if (err) *err = FrameReadError::TIMEOUT_BODY;
    return std::nullopt;
  }
  Hash32 checksum{};
  if (!read_exact_timed(fd, checksum.data(), checksum.size(), body_timeout_ms)) {
    if (err) *err = FrameReadError::TIMEOUT_BODY;
    return std::nullopt;
  }

  if (crypto::sha256d(payload) != checksum) {
    if (err) *err = FrameReadError::INVALID_CHECKSUM;
    return std::nullopt;
  }
  return Frame{*msg, payload};
}

bool write_frame_fd(int fd, const Frame& f, std::uint32_t magic, std::uint16_t proto_version) {
  const Bytes raw = encode_frame(f, magic, proto_version);
  return write_all(fd, raw.data(), raw.size());
}

}  // namespace selfcoin::p2p
