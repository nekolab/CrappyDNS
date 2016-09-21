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

#include "hosts.h"

#include <fstream>
#include <queue>
#include <string>

#include <arpa/nameser.h>

const std::string CrappyHosts::kRegexRuleKey = "/^regex$/";

enum class ParseHostsState { kInit, kConfig, kHost };
enum class ParseConfigState { kName, kIPList, kTerm };

CrPacket CrappyHosts::AssemblePacket(
    std::shared_ptr<u8_vec> request,
    std::list<std::shared_ptr<struct sockaddr_storage>> address_list) {
  auto dummy_srv = std::make_shared<CrDNSServer>(
      CrDNSServer{.health = CrDNSServer::Health::kTrusted});

  uint32_t ttl_32 = htonl(60 * 60 * 2);
  uint8_t* ttl = (uint8_t*)&ttl_32;
  uint16_t list_size_16 = htons(address_list.size());
  uint8_t* list_size = (uint8_t*)&list_size_16;
  auto it = std::find(request->begin() + 12, request->end(), 0x00);
  uint8_t type_hi = *(++it), type_lo = *(++it);

  std::shared_ptr<u8_vec> resp = std::make_shared<u8_vec>();
  resp->reserve(80);
  resp->insert(resp->cend(), request->begin(), request->begin() + 2);
  resp->insert(resp->cend(), {0x81, 0x80, 0x00, 0x01});
  resp->insert(resp->cend(), {*list_size, *(list_size + 1)});
  resp->insert(resp->cend(), {0x00, 0x00, 0x00, 0x00});
  resp->insert(resp->cend(), request->begin() + 12, it + 2 + 1);
  for (const auto& addr : address_list) {
    auto addr_in = (const struct sockaddr_in*)addr.get();
    auto sin_addr = (uint8_t*)&(addr_in->sin_addr);
    auto addr_len = get_addrlen(addr_in), rd_len = htons(addr_len);
    auto rd_length = (uint8_t*)&rd_len;
    resp->insert(resp->cend(), {0xC0, 0x0C, type_hi, type_lo, 0x00, 0x01});
    resp->insert(resp->cend(), {*ttl, *(ttl + 1), *(ttl + 2), *(ttl + 3)});
    resp->insert(resp->cend(), {*rd_length, *(rd_length + 1)});
    resp->insert(resp->cend(), sin_addr, sin_addr + addr_len);
  }
  return CrPacket{.payload = resp, .dns_server = dummy_srv, .addr = nullptr};
}

int CrappyHosts::LoadFile(const char* path) {
  std::string line;
  std::ifstream ifs(path);
  ParseHostsState state = ParseHostsState::kInit;

  if (!ifs)
    return -1;

  while (std::getline(ifs, line)) {
    if (line.size() == 0 || line[0] == '!')
      continue;
    switch (state) {
      case ParseHostsState::kInit:
        if (line == "[DNS Config]") {
          state = ParseHostsState::kConfig;
          break;
        }
        if (line == "[hosts]") {
          state = ParseHostsState::kHost;
          break;
        }
      case ParseHostsState::kHost: {
        auto rule = HostsRule::Parse(line.c_str(), dns_server_list_);
        if (rule == nullptr)
          break;
        std::string digest = rule->type_ != HostsRule::Type::kRegex
                                 ? rule->Digest()
                                 : CrappyHosts::kRegexRuleKey;
        digest_map_[digest].push_back(rule);
        break;
      }
      case ParseHostsState::kConfig:
        if (line == "[hosts]") {
          state = ParseHostsState::kHost;
        } else {
          char* strtok_save;
          char* config_item = strdup(line.c_str());
          char* token = strtok_r(config_item, "=", &strtok_save);
          ParseConfigState pc_state = ParseConfigState::kName;
          std::string dns_name;
          auto dns_list = std::make_shared<HostsRule::CrDNSServerList>();
          while (token != nullptr) {
            // trim token
            while (*token == ' ')
              ++token;
            char* token_tail = token + strlen((const char*)token);
            while (*(--token_tail) == ' ')
              *token_tail = '\0';

            switch (pc_state) {
              case ParseConfigState::kName:
                dns_name = std::string(token);
                pc_state = ParseConfigState::kIPList;
                break;
              case ParseConfigState::kIPList:
                if (!ParseDNSList(token, CrDNSServer::Health::kTrusted,
                                  *dns_list)) {
                  free(config_item);
                  return -1;
                }
                if (dns_list->size() == 0) {
                  free(config_item);
                  return -2;
                }
                dns_server_list_.push_back(std::make_pair(dns_name, dns_list));
                pc_state = ParseConfigState::kTerm;
                break;
              case ParseConfigState::kTerm:
                break;
            }
            token = strtok_r(nullptr, "=", &strtok_save);
          }
          free(config_item);
        }
        break;
    }
  }
  ifs.close();

  return 0;
}

std::shared_ptr<const HostsRule> CrappyHosts::Match(std::string hostname,
                                                    uint16_t type) {
  auto cmp = [&type](std::shared_ptr<const HostsRule>& lhs,
                     std::shared_ptr<const HostsRule>& rhs) {
    if (lhs->priority_ == rhs->priority_) {
      if (lhs->type_ == rhs->type_) {
        if (LIKELY((type & ns_t_a) == type)) {
          return lhs->ipv4_list_.size() < rhs->ipv4_list_.size();
        }
        return lhs->ipv6_list_.size() < rhs->ipv6_list_.size();
      }
      return lhs->type_ > rhs->type_;
    }
    return lhs->priority_ > rhs->priority_;
  };

  std::priority_queue<std::shared_ptr<const HostsRule>,
                      std::vector<std::shared_ptr<const HostsRule>>,
                      decltype(cmp)>
      candidate_rules(cmp);

  auto regex_rules_list = digest_map_[CrappyHosts::kRegexRuleKey];
  for (const auto& rule : regex_rules_list) {
    candidate_rules.push(rule);
  }

  for (const auto& digest_pair : digest_map_) {
    if (hostname.find(digest_pair.first) != std::string::npos) {
      for (const auto& rule : digest_pair.second) {
        candidate_rules.push(rule);
      }
    }
  }

  while (!candidate_rules.empty()) {
    auto rule = candidate_rules.top();
    if (rule->Match(hostname, type)) {
      return rule;
    }
    candidate_rules.pop();
  }

  return nullptr;
}
