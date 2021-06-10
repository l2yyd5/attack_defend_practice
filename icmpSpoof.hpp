#include <iostream>
#include <numeric>

#include "icmp_header.hpp"
#include "ipv4_header.hpp"
#include "myheader.h"
#include "raw.hpp"

#define SIZE_ETHERNET 14
const int bufSize = 1024;

class reping {
 private:
  int sequence_number_;
  std::string payload;
  std::string targetIP;
  std::string srcIP;
  ipv4_header ip;
  icmp_header echo_reply;
  boost::asio::ip::icmp::endpoint spoofed_endpoint;
  boost::asio::ip::icmp::endpoint receiver_endpoint;
  static unsigned short get_identifier() {
#if defined(BOOST_ASIO_WINDOWS)
    return static_cast<unsigned short>(::GetCurrentProcessId());
#else
    return static_cast<unsigned short>(::getpid());
#endif
  }
  void init(icmpheader tempicmp, const unsigned char *data, int len) {
    ip.version(4);
    ip.header_length(ip.size() / 4);
    ip.type_of_service(0);
    auto total_length = len;
    ip.total_length(total_length);
    ip.identification(get_identifier());
    ip.dont_fragment(false);
    ip.more_fragments(false);
    ip.fragment_offset(0);
    ip.time_to_live(64);
    ip.source_address(spoofed_endpoint.address().to_v4());
    ip.destination_address(receiver_endpoint.address().to_v4());
    ip.protocol(IPPROTO_ICMP);
    calculate_checksum(ip);
    echo_reply.type(icmp_header::echo_reply);
    echo_reply.code(0);
    auto tempid = tempicmp.icmp_id;
    int id1 = tempid / 0x100;
    int id2 = tempid % 0x100;
    tempid = id1 + (id2 << 8);
    echo_reply.identifier(tempid);
    auto tempseq = tempicmp.icmp_seq;
    int seq1 = tempseq / 0x100;
    int seq2 = tempseq % 0x100;
    tempseq = seq1 + (seq2 << 8);
    echo_reply.sequence_number(tempseq);
    char temp[len - SIZE_ETHERNET - ip.size() - echo_reply.size()];
    memcpy(temp, (data + SIZE_ETHERNET + ip.size() + echo_reply.size()), (len - SIZE_ETHERNET - ip.size() - echo_reply.size()));
    payload.append(temp, (len - SIZE_ETHERNET - ip.size() - echo_reply.size()));
    compute_checksum(echo_reply, payload.begin(), payload.end());
  }

 public:
  reping() {}
  ~reping() {}
  reping(std::string tIP, std::string sIP) : targetIP(tIP), srcIP(sIP), spoofed_endpoint(boost::asio::ip::address_v4::from_string(srcIP), 23333), receiver_endpoint(boost::asio::ip::address_v4::from_string(targetIP), 23333) {}
  void run(icmpheader tempicmp, const unsigned char *data, int len) {
    init(tempicmp, data, len);
    boost::asio::io_service io_service;
    boost::asio::basic_raw_socket<raw> sender(io_service,
                                              raw::endpoint(raw::v4(), 0));
    boost::array<boost::asio::const_buffer, 3> buffers = {{boost::asio::buffer(ip.data()),
                                                           boost::asio::buffer(echo_reply.data()),
                                                           boost::asio::buffer(payload)}};
    auto bytes_transferred = sender.send_to(buffers,
                                            raw::endpoint(receiver_endpoint.address(), receiver_endpoint.port()));
  }
};