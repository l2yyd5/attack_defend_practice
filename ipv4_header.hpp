#ifndef IPV4_HEADER_HPP
#define IPV4_HEADER_HPP

#include <algorithm>
#include <boost/array.hpp>
#include <boost/asio/ip/address_v4.hpp>

//  Mockup ipv4_header for with no options.
//
//  IPv4 wire format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-------+-------+-------+-------+-------+-------+-------+------+   ---
// |version|header |    type of    |    total length in bytes     |    ^
// |  (4)  | length|    service    |                              |    |
// +-------+-------+-------+-------+-------+-------+-------+------+    |
// |        identification         |flags|    fragment offset     |    |
// +-------+-------+-------+-------+-------+-------+-------+------+  20 bytes
// | time to live  |   protocol    |       header checksum        |    |
// +-------+-------+-------+-------+-------+-------+-------+------+    |
// |                      source IPv4 address                     |    |
// +-------+-------+-------+-------+-------+-------+-------+------+    |
// |                   destination IPv4 address                   |    v
// +-------+-------+-------+-------+-------+-------+-------+------+   ---
// /                       options (if any)                       /
// +-------+-------+-------+-------+-------+-------+-------+------+

class ipv4_header {
 public:
  ipv4_header() { std::fill(buffer_.begin(), buffer_.end(), 0); }

  void version(boost::uint8_t value) {
    buffer_[0] = (value << 4) | (buffer_[0] & 0x0F);
  }

  void header_length(boost::uint8_t value) {
    buffer_[0] = (value & 0x0F) | (buffer_[0] & 0xF0);
  }

  void type_of_service(boost::uint8_t value) { buffer_[1] = value; }
  void total_length(boost::uint16_t value) { encode16(2, value); }
  void identification(boost::uint16_t value) { encode16(4, value); }

  void dont_fragment(bool value) {
    buffer_[6] ^= (-value ^ buffer_[6]) & 0x40;
  }

  void more_fragments(bool value) {
    buffer_[6] ^= (-value ^ buffer_[6]) & 0x20;
  }

  void fragment_offset(boost::uint16_t value) {
    // Preserve flags.
    auto flags = static_cast<uint16_t>(buffer_[6] & 0xE0) << 8;
    encode16(6, (value & 0x1FFF) | flags);
  }

  void time_to_live(boost::uint8_t value) { buffer_[8] = value; }
  void protocol(boost::uint8_t value) { buffer_[9] = value; }
  void checksum(boost::uint16_t value) { encode16(10, value); }

  void source_address(boost::asio::ip::address_v4 value) {
    auto bytes = value.to_bytes();
    std::copy(bytes.begin(), bytes.end(), &buffer_[12]);
  }

  void destination_address(boost::asio::ip::address_v4 value) {
    auto bytes = value.to_bytes();
    std::copy(bytes.begin(), bytes.end(), &buffer_[16]);
  }

 public:
  std::size_t size() const { return buffer_.size(); }

  const boost::array<uint8_t, 20>& data() const { return buffer_; }

 private:
  void encode16(boost::uint8_t index, boost::uint16_t value) {
    buffer_[index] = (value >> 8) & 0xFF;
    buffer_[index + 1] = value & 0xFF;
  }

  boost::array<uint8_t, 20> buffer_;
};

void calculate_checksum(ipv4_header& header) {
  header.checksum(0);

  auto data = header.data();
  auto sum = std::accumulate<boost::uint16_t*, boost::uint32_t>(
      reinterpret_cast<boost::uint16_t*>(&data[0]),
      reinterpret_cast<boost::uint16_t*>(&data[0] + data.size()),
      0);

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  header.checksum(~sum);
}

#endif  // IPV4_HEADER_HPP