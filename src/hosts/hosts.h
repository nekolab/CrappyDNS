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

#ifndef _CR_HOSTS_H_
#define _CR_HOSTS_H_

#include <list>
#include <string>
#include <unordered_map>

#include "../crappydns.h"
#include "rule.h"

class CrappyHosts {
 public:
  CrappyHosts() : dns_server_list_(), digest_map_(){};
  ~CrappyHosts(){};

  static CrPacket AssemblePacket(
      std::shared_ptr<u8_vec> request,
      std::list<std::shared_ptr<struct sockaddr_storage>> address_list);

  int LoadFile(const char* path);
  std::shared_ptr<const HostsRule> Match(std::string, uint16_t);

 private:
  static const std::string kRegexRuleKey;
  std::list<HostsRule::CrDNSServerNameListPair> dns_server_list_;
  std::unordered_map<std::string, std::list<std::shared_ptr<const HostsRule>>>
      digest_map_;
};

#endif
