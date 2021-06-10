#include <sstream>

#include "ifname.h"
#include "sniff.h"

int main() {
  std::stringstream ss;
  ss << "proto ICMP and src " << targetIP;
  std::string filter_exp = ss.str();
  std::string filter(filter_exp.c_str());
  sniff *test = new sniff(filter);
  char ip[64];
  ifName interfaceName;
  interfaceName.getSubnetMask(ip, sizeof(ip));
  std::cout << "Please choose an interface to open live pcap" << std::endl;
  interfaceName.showinfo();
  std::cout << "Input name:";
  std::cin >> test->interFace;

  test->startPcap();
  delete test;

  return 0;
}