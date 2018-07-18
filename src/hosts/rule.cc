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

#include "rule.h"

#include <algorithm>

#include <arpa/nameser.h>

#include "../crappydns.h"

const std::regex HostsRule::kDigestRegex("[A-Za-z0-9-\\.]{3,}");

enum class ParseState { kInit, kPriority, kIPSrvList, kHostname, kTerm };

std::shared_ptr<const HostsRule> HostsRule::Parse(
    const char* raw_rule,
    std::list<CrDNSServerNameListPair> dns_server_group_list) {
  ParseState fsm_state = ParseState::kInit;

  HostsRule::Priority priority = HostsRule::Priority::kNotDefined;
  std::string hostname;
  CrDNSServerListPtr server_list = nullptr;
  std::list<std::shared_ptr<struct sockaddr_storage>> addr_list;

  char* strtok_save;
  char* hosts_rule = strdup(raw_rule);
  char* rule_token = strtok_r(hosts_rule, " ", &strtok_save);

  while (rule_token != nullptr) {
    switch (fsm_state) {
      case ParseState::kInit:
        fsm_state = rule_token[0] == '<' ? ParseState::kPriority
                                         : ParseState::kIPSrvList;
        break;
      case ParseState::kPriority: {
        char priority_ch;
        if (1 != sscanf(rule_token, "<%1[1-5]>", &priority_ch)) {
          WARN << "Not a valid priority in rule: " << raw_rule << ENDL;
          goto rule_parse_end;
        } else {
          priority = HostsRule::Priority(priority_ch - '0');
        }
        fsm_state = ParseState::kIPSrvList;
        rule_token = strtok_r(nullptr, " ", &strtok_save);
        break;
      }
      case ParseState::kIPSrvList:
        if (!ParseIPList(rule_token, addr_list)) {
          std::string token_string(rule_token);
          auto it = std::find_if(
              dns_server_group_list.begin(), dns_server_group_list.end(),
              [&token_string](const CrDNSServerNameListPair& item) {
                return item.first == token_string;
              });
          if (it != dns_server_group_list.end()) {
            server_list = it->second;
          } else {
            WARN << "Not a valid server config in rule: " << raw_rule << ENDL;
            goto rule_parse_end;
          }
        }
        fsm_state = ParseState::kHostname;
        rule_token = strtok_r(nullptr, " ", &strtok_save);
        break;
      case ParseState::kHostname:
        hostname = std::string(rule_token);
        fsm_state = ParseState::kTerm;
      case ParseState::kTerm:
        rule_token = strtok_r(nullptr, " ", &strtok_save);
        break;
    }
  }

rule_parse_end:
  free(hosts_rule);
  return fsm_state == ParseState::kTerm
             ? std::make_shared<HostsRule>(priority, hostname, server_list,
                                           addr_list)
             : nullptr;
}

HostsRule::HostsRule(
    HostsRule::Priority priority,
    std::string hostname,
    CrDNSServerListPtr server_list,
    std::list<std::shared_ptr<struct sockaddr_storage>> addr_list)
    : priority_(priority),
      addr_type_(0),
      dns_server_list_(server_list),
      ipv4_list_(),
      ipv6_list_(),
      host_(hostname),
      host_regex_() {
  // set default priority
  if (priority_ == Priority::kNotDefined) {
    if (addr_list.size())
      priority_ = Priority::kMediumHigh;
    if (host_.front() == '/')
      priority_ = Priority::kMedium;
    if (dns_server_list_ != nullptr)
      priority_ = Priority::kMediumLow;
  }

  // set addr type and fill different type list
  std::for_each(addr_list.begin(), addr_list.end(),
                [this](std::shared_ptr<struct sockaddr_storage>& addr) {
                  if (LIKELY(addr->ss_family == AF_INET)) {
                    this->addr_type_ |= ns_t_a;
                    ipv4_list_.push_back(addr);
                  } else if (addr->ss_family == AF_INET6) {
                    this->addr_type_ |= ns_t_aaaa;
                    ipv6_list_.push_back(addr);
                  }
                });

  // set type and build regex
  if (host_.front() == '/' && host_.back() == '/' && host_.size() > 2) {
    type_ = Type::kRegex;
    host_regex_ = std::regex(host_.substr(1, host_.length() - 2));
  } else if (host_.find('*') != std::string::npos ||
             host_.find('?') != std::string::npos) {
    type_ = Type::kWildcard;
    std::string regexp(host_);
    regexp.insert(0, "^");
    regexp.push_back('$');
    regexp = std::regex_replace(regexp, std::regex("\\."), "\\.");
    regexp = std::regex_replace(regexp, std::regex("\\?"), "[A-Za-z0-9-]+");
    regexp = std::regex_replace(regexp, std::regex("\\*"), "[A-Za-z0-9-\\.]+");
    host_regex_ = std::regex(regexp);
  } else {
    type_ = Type::kRaw;
  }
}

static bool match_comp(const std::smatch& lhs, const std::smatch& rhs) {
  return lhs.str().length() < rhs.str().length();
}

std::string HostsRule::Digest() const {
  if (type_ == Type::kRegex)
    return std::string();
  auto hosts_begin =
      std::sregex_iterator(host_.begin(), host_.end(), HostsRule::kDigestRegex);
  auto hosts_end = std::sregex_iterator();
  return std::max_element(hosts_begin, hosts_end, match_comp)->str();
}

bool HostsRule::Match(std::string domain, uint16_t type) const {
  switch (type_) {
    case Type::kRaw:
      return ((type & addr_type_) == type || dns_server_list_ != nullptr) &&
             host_ == domain;
    case Type::kWildcard:
    case Type::kRegex:
    default:
      return ((type & addr_type_) == type || dns_server_list_ != nullptr) &&
             std::regex_match(domain, host_regex_);
  }
}
