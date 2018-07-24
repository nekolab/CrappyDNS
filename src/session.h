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

#ifndef _CR_SESSION_H_
#define _CR_SESSION_H_

#include <string>

#include <arpa/nameser.h>

#include "crappydns.h"

class HostsRule;
class CrSessionManager;

class CrSession {
 public:
  CrSession(CrSessionManager* manager, CrPacket packet);
  ~CrSession();

  enum class Status {
    kBadRequest,
    kInit,
    kWaitHealth,
    kWaitFast,
    kResolved,
    kDedicated
  };

  Status status_;
  CrSessionManager* manager_;

  uint16_t raw_id_;
  uint16_t query_type_;
  uint16_t pipelined_id_;
  uint16_t response_on_the_way_;

  std::string query_name_;
  std::shared_ptr<u8_vec> request_payload_;
  std::shared_ptr<u8_vec> candidate_response_;
  std::shared_ptr<const HostsRule> matched_rule_;
  std::shared_ptr<struct sockaddr_storage> reply_to_;

  void Resolve(CrPacket& response, ns_msg& msg);
  void SetTimer(uv_loop_t* uv_loop, uint64_t timeout);
  void Transit(bool is_trusted_ip,
               bool is_healthy_dns,
               std::shared_ptr<u8_vec> rs);

 private:
  uv_timer_t* uv_timer_;
};

#endif
