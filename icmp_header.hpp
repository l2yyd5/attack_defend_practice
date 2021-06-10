#ifndef ICMP_HEADER_HPP
#define ICMP_HEADER_HPP

#include <algorithm>
#include <boost/array.hpp>
#include <istream>
#include <ostream>

// ICMP header for both IPv4 and IPv6.
//
// The wire format of an ICMP header is:
//
// 0               8               16                             31
// +---------------+---------------+------------------------------+      ---
// |               |               |                              |       ^
// |     type      |     code      |          checksum            |       |
// |               |               |                              |       |
// +---------------+---------------+------------------------------+    8 bytes
// |                               |                              |       |
// |          identifier           |       sequence number        |       |
// |                               |                              |       v
// +-------------------------------+------------------------------+      ---

class icmp_header {
 public:
  enum { echo_reply = 0,
         destination_unreachable = 3,
         source_quench = 4,
         redirect = 5,
         echo_request = 8,
         time_exceeded = 11,
         parameter_problem = 12,
         timestamp_request = 13,
         timestamp_reply = 14,
         info_request = 15,
         info_reply = 16,
         address_request = 17,
         address_reply = 18 };

  icmp_header() { std::fill(buffer_.begin(), buffer_.end(), 0); }
  std::size_t size() const { return buffer_.size(); }
  const boost::array<uint8_t, 8>& data() const { return buffer_; }

  unsigned char type() const { return buffer_[0]; }
  unsigned char code() const { return buffer_[1]; }
  unsigned short checksum() const { return decode(2, 3); }
  unsigned short identifier() const { return decode(4, 5); }
  unsigned short sequence_number() const { return decode(6, 7); }

  void type(unsigned char n) { buffer_[0] = n; }
  void code(unsigned char n) { buffer_[1] = n; }
  void checksum(unsigned short n) { encode(2, 3, n); }
  void identifier(unsigned short n) { encode(4, 5, n); }
  void sequence_number(unsigned short n) { encode(6, 7, n); }

 private:
  unsigned short decode(int a, int b) const { return (buffer_[a] << 8) + buffer_[b]; }

  void encode(int a, int b, unsigned short n) {
    buffer_[a] = static_cast<unsigned char>(n >> 8);
    buffer_[b] = static_cast<unsigned char>(n & 0xFF);
  }

  boost::array<uint8_t, 8> buffer_;
};

template <typename Iterator>
void compute_checksum(icmp_header& header,
                      Iterator body_begin, Iterator body_end) {
  unsigned int sum = (header.type() << 8) + header.code() + header.identifier() + header.sequence_number();

  Iterator body_iter = body_begin;
  while (body_iter != body_end) {
    sum += (static_cast<unsigned char>(*body_iter++) << 8);
    if (body_iter != body_end)
      sum += static_cast<unsigned char>(*body_iter++);
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  header.checksum(static_cast<unsigned short>(~sum));
}

#endif  // ICMP_HEADER_HPP