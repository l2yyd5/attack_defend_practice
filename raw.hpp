#ifndef RAW_HPP
#define RAW_HPP

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/cstdint.hpp>

class raw {
 public:
  typedef boost::asio::ip::basic_endpoint<raw> endpoint;

  typedef boost::asio::basic_raw_socket<raw> socket;

  typedef boost::asio::ip::basic_resolver<raw> resolver;

  static raw v4() {
    return raw(IPPROTO_RAW, PF_INET);
  }

  static raw v6() {
    return raw(IPPROTO_RAW, PF_INET6);
  }

  explicit raw()
      : protocol_(IPPROTO_RAW),
        family_(PF_INET) {}

  int type() const {
    return SOCK_RAW;
  }

  int protocol() const {
    return protocol_;
  }

  int family() const {
    return family_;
  }

  friend bool operator==(const raw& p1, const raw& p2) {
    return p1.protocol_ == p2.protocol_ && p1.family_ == p2.family_;
  }

  friend bool operator!=(const raw& p1, const raw& p2) {
    return !(p1 == p2);
  }

 private:
  explicit raw(int protocol_id, int protocol_family)
      : protocol_(protocol_id),
        family_(protocol_family) {}

  int protocol_;
  int family_;
};

#endif