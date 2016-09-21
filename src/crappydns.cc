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

#include "crappydns.h"

#include "hosts/hosts.h"
#include "trusted_net.h"

// CrConfig static initialization
bool CrConfig::verbose_mode(false);
uint64_t CrConfig::timeout_in_ms(3000);
CrappyHosts CrConfig::hosts = {};
CrTrustedNet CrConfig::trusted_net = {};
struct sockaddr_storage CrConfig::listen_addr = {};
std::list<std::shared_ptr<CrDNSServer>> CrConfig::dns_list({});

bool CrDNSServer::operator==(const CrDNSServer& rhs) const {
  return health == rhs.health && proctol == rhs.proctol &&
         0 == cmp_sockaddr((const struct sockaddr*)this,
                           (const struct sockaddr*)&rhs);
}

std::ostream& operator<<(std::ostream& out, const CrDNSServer& server) {
  if (server.addr == nullptr &&
      server.health == CrDNSServer::Health::kTrusted) {
    out << "hosts";
    return out;
  }

  switch (server.proctol) {
    case CrDNSServer::Proctol::kUDP:
      out << "udp://";
      break;
    case CrDNSServer::Proctol::kTCP:
      out << "tcp://";
      break;
    case CrDNSServer::Proctol::kGHTTPS:
      out << "ghttps://";
      break;
  }
  out << *(SockAddr*)server.addr.get();
  return out;
}
