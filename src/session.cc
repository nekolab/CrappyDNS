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

#include "session.h"

#include <arpa/nameser_compat.h>

#include "hosts/hosts.h"
#include "hosts/rule.h"
#include "session_manager.h"
#include "trusted_net.h"

CrSession::CrSession(CrSessionManager* manager, CrPacket packet)
    : status_(Status::kInit),
      manager_(manager),
      raw_id_(0),
      query_type_(0),
      pipelined_id_(0),
      response_on_the_way_(0),
      query_name_(),
      request_payload_(packet.payload),
      candidate_response_(nullptr),
      matched_rule_(nullptr),
      reply_to_(packet.addr),
      uv_timer_(nullptr) {
  ns_msg msg;
  if (ns_initparse((const unsigned char*)request_payload_->data(),
                   request_payload_->size(), &msg) < 0) {
    // TODO: Prompt dns parse error
    status_ = Status::kBadRequest;
    return;
  }

  raw_id_ = ns_msg_id(msg);
  pipelined_id_ = manager->GenPipelinedID();

  ns_put16(pipelined_id_, (unsigned char*)request_payload_->data());

  ns_rr rr;
  uint16_t qdcount = ns_msg_count(msg, ns_s_qd);
  if (qdcount >= 1 && ns_parserr(&msg, ns_s_qd, 0, &rr) == 0 &&
      (ns_rr_type(rr) == ns_t_a || ns_rr_type(rr) == ns_t_aaaa)) {
    query_name_ = ns_rr_name(rr);
    query_type_ = ns_rr_type(rr);
    matched_rule_ = CrConfig::hosts.Match(query_name_, query_type_);
    if (matched_rule_ != nullptr) {
      status_ = Status::kDedicated;
    }
    VERB("[" << pipelined_id_ << "] Query " << raw_id_ << ": " << query_name_);
  }
}

CrSession::~CrSession() {
  if (uv_timer_ != nullptr) {
    uv_timer_stop(uv_timer_);
    uv_close((uv_handle_t*)uv_timer_,
             [](uv_handle_t* handle) { delete handle; });
  }
}

void CrSession::SetTimer(uv_loop_t* uv_loop, uint64_t timeout) {
  uv_timer_ = new uv_timer_t;
  uv_timer_->data = this;
  uv_timer_init(uv_loop, uv_timer_);
  uv_timer_start(
      uv_timer_,
      [](uv_timer_t* handle) {
        CrSession* session = (CrSession*)handle->data;
        session->manager_->Resolve(session->pipelined_id_);
      },
      timeout, 0);
}

void CrSession::Resolve(CrPacket& response, ns_msg& msg) {
  --response_on_the_way_;

  uint16_t rrmax = ns_msg_count(msg, ns_s_an);
  if (rrmax == 0) {
    candidate_response_ = response.payload;
  } else {
    ns_rr rr;
    for (uint16_t rrnum = 0; rrnum < rrmax; ++rrnum) {
      if (ns_parserr(&msg, ns_s_an, rrnum, &rr) == 0) {
        u_int type = ns_rr_type(rr);
        const u_char* rd = ns_rr_rdata(rr);

        bool from_healthy_dns =
            response.dns_server->health == CrDNSServer::Health::kHealthy;

        if (type == ns_t_a) {
          bool in_trusted_net =
              CrConfig::trusted_net.Contains(ntohl(*(uint32_t*)rd));
          // VERB("[" << pipelined_id_ << "] [A]"
          //          << (from_healthy_dns ? "[HEALTHY] " : "[UNHEALTHY]")
          //          << (in_trusted_net ? "[TRUSTED]" : "[UNTRUSTED]")
          //          << " Got " << (int)*rd << "." << (int)*(rd + 1)
          //          << "." << (int)*(rd + 2)  << "." << (int)*(rd + 3)
          //          << " from " << *response.dns_server);
          Transit(in_trusted_net, from_healthy_dns, response.payload);
        } else {
          // VERB("[" << pipelined_id_ << "] [OTHER]"
          //          << (from_healthy_dns ? "[HEALTHY] " : "[UNHEALTHY]")
          //          << " Got response from " << *response.dns_server);
          if (status_ == Status::kInit || status_ == Status::kWaitHealth) {
            candidate_response_ = response.payload;
          }
        }
      }
    }
  }

  if (response_on_the_way_ == 0 || status_ == Status::kResolved) {
    manager_->Resolve(pipelined_id_);
  }
}

void CrSession::Transit(bool in_trusted_net,
                        bool from_healthy_dns,
                        std::shared_ptr<u8_vec> response) {
  switch (status_) {
    case Status::kInit:
      if (!from_healthy_dns && in_trusted_net) {
        status_ = Status::kResolved;
      } else if (!from_healthy_dns && !in_trusted_net) {
        status_ = Status::kWaitHealth;
      } else {
        status_ = Status::kWaitFast;
      }
      candidate_response_ = response;
      break;
    case Status::kWaitHealth:
      if (from_healthy_dns || in_trusted_net) {
        candidate_response_ = response;
        status_ = Status::kResolved;
      }
      break;
    case Status::kWaitFast:
      if (from_healthy_dns && in_trusted_net) {
        candidate_response_ = response;
      } else if (!from_healthy_dns && in_trusted_net) {
        candidate_response_ = response;
        status_ = Status::kResolved;
      }
      break;
    case Status::kDedicated:
      candidate_response_ = response;
      status_ = Status::kResolved;
      break;
    case Status::kBadRequest:
    case Status::kResolved:
      break;
  }
}
