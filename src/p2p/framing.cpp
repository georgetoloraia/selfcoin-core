#include "p2p/framing.hpp"

#include <sys/socket.h>
#include <unistd.h>

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

std::optional<Frame> read_frame_fd(int fd, std::size_t max_payload_len, std::uint32_t expected_magic,
                                   std::uint16_t expected_proto_version) {
  std::array<std::uint8_t, 12> hdr{};
  if (!read_exact(fd, hdr.data(), hdr.size())) return std::nullopt;

  codec::ByteReader r(Bytes(hdr.begin(), hdr.end()));
  auto magic = r.u32le();
  auto version = r.u16le();
  auto msg = r.u16le();
  auto len = r.u32le();
  if (!magic || !version || !msg || !len) return std::nullopt;
  if (*magic != expected_magic || *version != expected_proto_version || *len > max_payload_len) return std::nullopt;

  Bytes payload(*len);
  if (*len > 0 && !read_exact(fd, payload.data(), payload.size())) return std::nullopt;
  Hash32 checksum{};
  if (!read_exact(fd, checksum.data(), checksum.size())) return std::nullopt;

  if (crypto::sha256d(payload) != checksum) return std::nullopt;
  return Frame{*msg, payload};
}

bool write_frame_fd(int fd, const Frame& f, std::uint32_t magic, std::uint16_t proto_version) {
  const Bytes raw = encode_frame(f, magic, proto_version);
  return write_all(fd, raw.data(), raw.size());
}

}  // namespace selfcoin::p2p
