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

#ifndef _CR_CRAPPYDNS_H_
#define _CR_CRAPPYDNS_H_

#include <cstdint>
#include <list>
#include <memory>
#include <ostream>
#include <vector>

#include <sys/socket.h>

#include <uv.h>

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#ifndef VERSION
#define VERSION "development"
#endif

#define UDP_BUF_SIZE 640
#define TCP_BUF_SIZE 1024

class CrappyHosts;
class CrTrustedNet;

typedef std::vector<uint8_t> u8_vec;

struct CrDNSServer {
  enum class Proctol { kUDP, kTCP, kGHTTPS };
  enum class Health { kHealthy, kPoisoned, kTrusted };

  Health health;
  Proctol proctol;
  std::shared_ptr<struct sockaddr_storage> addr;

  bool operator==(const CrDNSServer& rhs) const;
  friend std::ostream& operator<<(std::ostream& out, const CrDNSServer& server);
};

struct CrPacket {
  std::shared_ptr<u8_vec> payload;
  std::shared_ptr<const CrDNSServer> dns_server;
  std::shared_ptr<struct sockaddr_storage> addr;
};

struct CrConfig {
  static bool debug_mode;
  static bool verbose_mode;
  static uint64_t timeout_in_ms;
  static const char* run_as_user;
  static CrappyHosts hosts;
  static CrTrustedNet trusted_net;
  static struct sockaddr_storage listen_addr;
  static std::list<std::shared_ptr<CrDNSServer>> dns_list;
};

#include "utils.h"

#endif
