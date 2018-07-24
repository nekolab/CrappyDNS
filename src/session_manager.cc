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

#include "session_manager.h"

#include <arpa/nameser.h>

#include "hosts/hosts.h"
#include "hosts/rule.h"
#include "server.h"
#include "session.h"

CrSessionManager::CrSessionManager(uv_loop_t* loop, CrappyServer* server)
    : timeout_(CrConfig::timeout_in_ms),
      uv_loop_(loop),
      sender_(loop),
      server_(server),
      pool_() {
  std::random_device rd;
  counter_ = (uint16_t)rd();
  mr_step_.seed(rd());

  PrepareServer();
  PrepareSender();
  GenShuffleSequence(rd());
}

std::shared_ptr<CrSession> CrSessionManager::Create(CrPacket packet) {
  auto session = std::make_shared<CrSession>(this, packet);
  if (session->status_ != CrSession::Status::kBadRequest) {
    session->SetTimer(uv_loop_, timeout_);
    pool_[session->pipelined_id_] = session;
    return session;
  }
  return nullptr;
}

std::shared_ptr<CrSession> CrSessionManager::Get(uint16_t pipelined_id) {
  if (pool_.find(pipelined_id) != pool_.end()) {
    return pool_[pipelined_id];
  }
  return nullptr;
}

bool CrSessionManager::Has(uint16_t pipelined_id) {
  return pool_.find(pipelined_id) != pool_.end();
}

void CrSessionManager::Destory(uint16_t pipelined_id) {
  pool_.erase(pipelined_id);
}

bool CrSessionManager::Dispatch(uint16_t pipelined_id) {
  auto session = Get(pipelined_id);
  if (session == nullptr)
    return false;
  if (session->status_ == CrSession::Status::kDedicated) {
    auto rule = session->matched_rule_;
    if (rule->dns_server_list_ != nullptr) {
      for (const auto& server : *rule->dns_server_list_) {
        sender_.SendTo(session, server);
        ++session->response_on_the_way_;
      }
      return true;
    }

    auto qtype = session->query_type_;
    if (LIKELY(qtype == ns_t_a && rule->ipv4_list_.size() != 0)) {
      OnRemoteRecv(CrappyHosts::AssemblePacket(session->request_payload_,
                                               rule->ipv4_list_));
      return true;
    } else if (qtype == ns_t_aaaa && rule->ipv6_list_.size() != 0) {
      OnRemoteRecv(CrappyHosts::AssemblePacket(session->request_payload_,
                                               rule->ipv6_list_));
      return true;
    }
  }

  sender_.Send(session);
  return true;
}

void CrSessionManager::OnRemoteRecv(CrPacket response) {
  ns_msg msg;

  if (ns_initparse((const unsigned char*)response.payload->data(),
                   response.payload->size(), &msg) < 0) {
    INFO << "Packet from " << *response.dns_server << " parse error " << ENDL;
    return;
  }

  uint16_t pipelined_id = ns_msg_id(msg);
  VERB("[" << pipelined_id << "] Received response from "
           << *response.dns_server);
  auto session = Get(pipelined_id);
  if (session != nullptr) {
    session->Resolve(response, msg);
  }
}

void CrSessionManager::Resolve(uint16_t pipelined_id) {
  auto session = Get(pipelined_id);
  Destory(pipelined_id);
  if (session == nullptr || session->candidate_response_ == nullptr ||
      session->candidate_response_->size() <= 2) {
    return;
  }
  ns_put16(session->raw_id_,
           (unsigned char*)session->candidate_response_->data());
  server_->Send(session);
  VERB("[" << session->pipelined_id_ << "] Session resolved");
}

void CrSessionManager::PrepareServer() {
  server_->recv_cb_ = [this](CrPacket packet) {
    VERB("[Server] Request received from " << *(SockAddr*)(packet.addr.get()));
    auto session = this->Create(packet);
    if (session == nullptr)
      return;
    this->Dispatch(session->pipelined_id_);
  };
}

void CrSessionManager::PrepareSender() {
  sender_.send_cb_ = [this](uint16_t session_id,
                            std::shared_ptr<const CrDNSServer> server,
                            int status) {
    VERB("[" << session_id << "] Send to " << *server << ", "
             << *(UVError*)&status);
    if (status != 0) {
      auto session = this->Get(session_id);
      if (session) {
        --session->response_on_the_way_;
      }
    }
  };

  sender_.recv_cb_ = [this](CrPacket response) {
    VERB("[Worker] Recved " << response.payload->size() << " bytes from "
                            << *response.dns_server);
    this->OnRemoteRecv(response);
  };

  for (auto&& dns_server : CrConfig::dns_list) {
    sender_.RegisterDNSServer(dns_server);
  }
}

void CrSessionManager::GenShuffleSequence(uint_fast32_t seed) {
  std::minstd_rand mr(seed);
  for (int i = 0; i < kShuffleTimes; ++i) {
    std::uniform_int_distribution<> uid(i, kShuffleTimes);
    shuffle_seq_[i] = uid(mr);
  }

  if (CrConfig::verbose_mode) {
    uint8_t pokers[16];
    for (size_t i = 0; i < 16; ++i)
      pokers[i] = i;
    for (size_t i = 0, j; i < kShuffleTimes; ++i) {
      j = shuffle_seq_[i];
      uint8_t val = pokers[i];
      pokers[i] = pokers[j];
      pokers[j] = val;
    }
    VERB_R("[Init] Shuffle param: [ ");
    for (size_t i = 0; i < 16; ++i)
      VERB_S << unsigned(pokers[i]) << " ";
    VERB_S << "]" << ENDL;
  }
}

uint16_t CrSessionManager::GenPipelinedID() {
  counter_ += mr_step_() % 97 + 1;
  uint16_t counter = counter_, mask = 0;

  // magic to counter
  for (size_t i = 0, j = 0; i < kShuffleTimes; ++i) {
    j = shuffle_seq_[i];
    mask = ((counter >> i) & 1) ^ ((counter >> j) & 1);
    counter ^= (mask << i) | (mask << j);
  }

  VERB("[" << counter << "] Session ID generated from " << counter_);
  return counter;
}
