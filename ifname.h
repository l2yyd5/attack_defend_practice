#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

class ifName {
 private:
  int size;
  std::vector<std::string> interfaceName;
  std::vector<std::string> ipAddress;
  std::vector<std::string> broadcast;
  std::vector<std::string> subnetMask;

 public:
  int getSubnetMask(char ip[], int len) {
    struct sockaddr_in *sin = NULL;
    struct ifaddrs *ifa = NULL, *ifList;
    if (getifaddrs(&ifList) < 0) {
      return -1;
    }
    int i = 0;
    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr->sa_family == AF_INET) {
        i++;
        std::string ifname(ifa->ifa_name);
        interfaceName.push_back(ifname);

        sin = (struct sockaddr_in *)ifa->ifa_addr;
        std::string ifaddr(inet_ntoa(sin->sin_addr));
        ipAddress.push_back(ifaddr);

        sin = (struct sockaddr_in *)ifa->ifa_dstaddr;
        std::string ifbroad(inet_ntoa(sin->sin_addr));
        broadcast.push_back(ifbroad);

        sin = (struct sockaddr_in *)ifa->ifa_netmask;
        std::string ifnetmask(inet_ntoa(sin->sin_addr));
        subnetMask.push_back(ifbroad);
      }
    }
    size = i;
    freeifaddrs(ifList);
    return -1;
  }

  void showinfo() {
    for (int i = 0; i < size; i++) {
      std::cout << interfaceName[i] << std::endl;
    }
  }
};