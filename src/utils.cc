/*
 * Copyright (C) 2016  Sunny <ratsunny@gmail.com>
 *
 * This file is part of CrappyDNS.
 *
 * CrappyDNS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CrappyDNS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "utils.h"

#include <uv.h>

std::ostream __null_stream(nullptr);

bool ParseIP(const char* ip_str,
             uint16_t& port,
             std::shared_ptr<struct sockaddr_storage>& result) {
  int rtn = 0;
  if (ip_str[0] == '[') {  // must be an ipv6 address with port
    char ip_addr[INET6_ADDRSTRLEN];
    rtn = sscanf(ip_str, "[%46[A-Za-z0-9:]]:%hu", ip_addr, &port);
    if (rtn < 1) {
      return false;
    }
    rtn = uv_ip6_addr(ip_addr, port, (struct sockaddr_in6*)result.get());
    if (rtn == UV_EINVAL) {
      return false;
    }
  } else {  // could be an ipv6 address without port or any ipv4 address
    rtn = uv_ip6_addr(ip_str, port, (struct sockaddr_in6*)result.get());
    if (rtn == UV_EINVAL) {  // not ipv6
      char ip_addr[INET_ADDRSTRLEN];
      rtn = sscanf(ip_str, "%16[0-9.]:%hu", ip_addr, &port);
      if (rtn < 1) {
        return false;
      }
      rtn = uv_ip4_addr(ip_addr, port, (struct sockaddr_in*)result.get());
      if (rtn == UV_EINVAL) {
        return false;
      }
    }
  }
  return true;
}

bool ParseIPList(const char* str,
                 std::list<std::shared_ptr<struct sockaddr_storage>>& result) {
  char *ip_list = strdup(str), *strtok_save;
  char* ip_addr = strtok_r(ip_list, ",", &strtok_save);
  while (ip_addr != nullptr) {
    uint16_t port = 53;
    while (ip_addr[0] == ' ')
      ++ip_addr;
    auto sockaddr = std::make_shared<struct sockaddr_storage>();
    if (!ParseIP(ip_addr, port, sockaddr)) {
      free(ip_list);
      return false;
    }
    result.push_back(sockaddr);
    ip_addr = strtok_r(nullptr, ",", &strtok_save);
  }
  free(ip_list);
  return true;
}

bool ParseDNSList(const char* str,
                  CrDNSServer::Health healthy,
                  std::list<std::shared_ptr<CrDNSServer>>& result) {
  char *dns_list = strdup(str), *strtok_save;
  char* dns_item = strtok_r(dns_list, ",", &strtok_save);
  while (dns_item != nullptr) {
    uint16_t port = 53;
    while (dns_item[0] == ' ')
      ++dns_item;
    char* ip_head = strstr(dns_item, "://");
    auto sockaddr = std::make_shared<struct sockaddr_storage>();
    CrDNSServer::Proctol proctol = CrDNSServer::Proctol::kUDP;

    if (ip_head != nullptr) {
      char proctol_str[7] = {'\0'};
      if (1 != sscanf(dns_item, "%6[udtcp]", proctol_str)) {
        free(dns_list);
        return false;
      } else if (strncmp(proctol_str, "udp", 3) == 0) {
        proctol = CrDNSServer::Proctol::kUDP;
      } else if (strncmp(proctol_str, "tcp", 3) == 0) {
        proctol = CrDNSServer::Proctol::kTCP;
      } else {
        free(dns_list);
        return false;
      }
      ip_head += 3;
    } else {
      ip_head = dns_item;
    }

    if (!ParseIP(ip_head, port, sockaddr)) {
      free(dns_list);
      return false;
    }

    result.push_back(std::make_shared<CrDNSServer>(
        CrDNSServer{.health = healthy, .proctol = proctol, .addr = sockaddr}));

    dns_item = strtok_r(nullptr, ",", &strtok_save);
  }
  free(dns_list);
  return true;
}

std::ostream& operator<<(std::ostream& out, const UVError& error) {
  if (error.error == 0) {
    out << "OK";
  } else {
    out << uv_err_name(error.error);
    // out << ": " << uv_strerror(error);
  }
  return out;
}

std::ostream& operator<<(std::ostream& out, const SockAddr& addr) {
  if (LIKELY(addr.payload.ss_family == AF_INET)) {
    char ip_str[INET_ADDRSTRLEN];
    auto add_v4 = (const struct sockaddr_in*)&(addr.payload);
    inet_ntop(AF_INET, &add_v4->sin_addr, (char*)ip_str, INET_ADDRSTRLEN);
    out << (const char*)ip_str << ":" << ntohs(add_v4->sin_port);
  } else if (addr.payload.ss_family == AF_INET6) {
    char ip_str[INET6_ADDRSTRLEN];
    auto add_v6 = (const struct sockaddr_in6*)&(addr.payload);
    inet_ntop(AF_INET6, &add_v6->sin6_addr, (char*)ip_str, INET6_ADDRSTRLEN);
    out << "[" << (const char*)ip_str << "]:" << ntohs(add_v6->sin6_port);
  } else {
    out << "[Unknow AF_TYPE address]";
  }
  return out;
}
