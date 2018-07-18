/*
 * Copyright (C) 2018  Sunny <ratsunny@gmail.com>
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

#ifndef _CR_UTILS_H_
#define _CR_UTILS_H_

#include <cstring>
#include <ctime>
#include <functional>
#include <iostream>

#include <netinet/in.h>
#include <sys/socket.h>

#include "crappydns.h"

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

extern std::ostream __null_stream;

#define __LOG(stream, is_verbose, with_time, prefix)                       \
  if (!is_verbose || CrConfig::verbose_mode) {                             \
    std::time_t __now;                                                     \
    std::time(&__now);                                                     \
    char __log_time_buf[10];                                               \
    std::strftime(__log_time_buf, 10, "%H:%M:%S", std::localtime(&__now)); \
    if (with_time) {                                                       \
      stream << "[" << (const char*)__log_time_buf << "]" << std::flush;   \
    }                                                                      \
    stream << prefix << std::flush;                                        \
  }                                                                        \
  ((!is_verbose || CrConfig::verbose_mode) ? stream : __null_stream)

#define LOG __LOG(std::cout, false, true, "[LOG] ")
#define ERR __LOG(std::cerr, false, true, "[ERR] ")
#define VERB __LOG(std::cout, true, true, "[VERB] ")
#define WARN __LOG(std::cout, false, true, "[WARN] ")
#define INFO __LOG(std::cout, false, true, "[INFO] ")

#define ENDL std::endl

template <class T>
inline void hash_combine(std::size_t& seed, const T& v) {
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

namespace std {
template <>
struct hash<sockaddr_storage> {
  std::size_t operator()(const sockaddr_storage& s) const {
    std::size_t seed = 0;
    hash_combine<int>(seed, s.ss_family);
    if (LIKELY(s.ss_family == AF_INET)) {
      auto p = (const sockaddr_in*)&s;
      hash_combine<uint16_t>(seed, p->sin_port);
      hash_combine<char32_t>(seed, p->sin_addr.s_addr);
    } else if (s.ss_family == AF_INET6) {
      auto p = (const sockaddr_in6*)&s;
      hash_combine<uint16_t>(seed, p->sin6_port);
      hash_combine<char32_t>(seed, p->sin6_flowinfo);
      hash_combine<char32_t>(seed, *(char32_t*)(p->sin6_addr.s6_addr + 0));
      hash_combine<char32_t>(seed, *(char32_t*)(p->sin6_addr.s6_addr + 4));
      hash_combine<char32_t>(seed, *(char32_t*)(p->sin6_addr.s6_addr + 8));
      hash_combine<char32_t>(seed, *(char32_t*)(p->sin6_addr.s6_addr + 12));
      hash_combine<char32_t>(seed, p->sin6_scope_id);
    }
    return seed;
  }
};

template <>
struct hash<CrDNSServer> {
  std::size_t operator()(const CrDNSServer& s) const {
    std::size_t seed = 0;
    hash_combine(seed, static_cast<int>(s.health));
    hash_combine(seed, static_cast<int>(s.proctol));
    hash_combine(seed, *s.addr);
    return seed;
  }
};
}  // namespace std

inline unsigned int get_sockaddr_size(const struct sockaddr* addr) {
  unsigned int addr_size = 0;
  if (LIKELY(addr->sa_family == AF_INET))
    addr_size = sizeof(struct sockaddr_in);
  else if (addr->sa_family == AF_INET6)
    addr_size = sizeof(struct sockaddr_in6);
  return addr_size;
}

inline uint16_t get_addrlen(const struct sockaddr_in* addr) {
  unsigned int addrlen = 0;
  if (LIKELY(addr->sin_family == AF_INET))
    addrlen = sizeof(struct in_addr);
  else if (addr->sin_family == AF_INET6)
    addrlen = sizeof(struct in6_addr);
  return addrlen;
}

inline int cmp_sockaddr(const struct sockaddr* x, const struct sockaddr* y) {
#define MEMCMP(a, b, c)          \
  do {                           \
    int rtn = ::memcmp(a, b, c); \
    if (rtn != 0)                \
      return rtn;                \
  } while (0)
#define CMP(a, b) \
  if (a != b)     \
  return a > b ? 1 : -1

  CMP(x->sa_family, y->sa_family);
  if (LIKELY(x->sa_family == AF_INET)) {
    const struct sockaddr_in *x_in = (const struct sockaddr_in*)x,
                             *y_in = (const struct sockaddr_in*)y;
    CMP(x_in->sin_port, y_in->sin_port);
    MEMCMP(&x_in->sin_addr, &y_in->sin_addr, sizeof(struct in_addr));
  } else if (x->sa_family == AF_INET6) {
    const struct sockaddr_in6 *x_in6 = (const struct sockaddr_in6*)x,
                              *y_in6 = (const struct sockaddr_in6*)y;
    CMP(x_in6->sin6_port, y_in6->sin6_port);
    CMP(x_in6->sin6_flowinfo, y_in6->sin6_flowinfo);
    CMP(x_in6->sin6_scope_id, y_in6->sin6_scope_id);
    MEMCMP(&x_in6->sin6_addr, &y_in6->sin6_addr, sizeof(struct in6_addr));
  } else {
    return -1;
  }
  return 0;

#undef CMP
#undef MEMCMP
}

bool ParseIP(const char* ip_str,
             uint16_t& port,
             std::shared_ptr<struct sockaddr_storage>& result);
bool ParseIPList(const char* str,
                 std::list<std::shared_ptr<struct sockaddr_storage>>& result);
bool ParseDNSList(const char* str,
                  CrDNSServer::Health healthy,
                  std::list<std::shared_ptr<CrDNSServer>>& result);

struct UVError {
  int error;
  friend std::ostream& operator<<(std::ostream&, const UVError&);
};

struct SockAddr {
  struct sockaddr_storage payload;
  friend std::ostream& operator<<(std::ostream&, const SockAddr&);
};

#endif
