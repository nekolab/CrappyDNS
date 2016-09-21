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

#ifndef _CR_HOSTS_RULE_H_
#define _CR_HOSTS_RULE_H_

#include <list>
#include <memory>
#include <regex>
#include <string>

#include <sys/socket.h>

struct CrDNSServer;

class HostsRule {
 public:
  using CrDNSServerList = std::list<std::shared_ptr<CrDNSServer>>;
  using CrDNSServerListPtr = std::shared_ptr<CrDNSServerList>;
  using CrDNSServerNameListPair = std::pair<std::string, CrDNSServerListPtr>;

  enum class Type { kRaw, kWildcard, kRegex };
  enum class Priority {
    kNotDefined,
    kHigh,
    kMediumHigh,
    kMedium,
    kMediumLow,
    kLow
  };

  HostsRule(Priority priority,
            std::string hostname,
            CrDNSServerListPtr server_list,
            std::list<std::shared_ptr<struct sockaddr_storage>> addr_list);
  ~HostsRule(){};

  Type type_;
  Priority priority_;
  uint16_t addr_type_;
  CrDNSServerListPtr dns_server_list_;
  std::list<std::shared_ptr<struct sockaddr_storage>> ipv4_list_;
  std::list<std::shared_ptr<struct sockaddr_storage>> ipv6_list_;

  static std::shared_ptr<const HostsRule> Parse(
      const char*,
      std::list<CrDNSServerNameListPair>);

  std::string Digest() const;
  bool Match(std::string domain, uint16_t type) const;

 private:
  static const std::regex kDigestRegex;

  std::string host_;
  std::regex host_regex_;
};

#endif
