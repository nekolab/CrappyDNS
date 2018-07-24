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

#include "sender.h"

#include "session.h"
#include "worker/tcp_worker.h"
#include "worker/udp_worker.h"
#include "worker/worker.h"

std::shared_ptr<CrWorker> CreateWorker(
    uv_loop_t* uv_loop,
    std::shared_ptr<const CrDNSServer> server) {
  std::shared_ptr<CrWorker> worker;
  switch (server->proctol) {
    case CrDNSServer::Proctol::kUDP:
      return std::make_shared<UDPWorker>(uv_loop, server);
      break;
    case CrDNSServer::Proctol::kTCP:
      return std::make_shared<TCPWorker>(uv_loop, server);
      break;
    default:
      return nullptr;
  }
}

std::shared_ptr<CrWorker> CrappySender::RegisterDNSServer(
    std::shared_ptr<const CrDNSServer> server) {
  auto worker = CreateWorker(uv_loop_, server);
  if (worker != nullptr) {
    worker->recv_cb_ = recv_cb_;
    worker->send_cb_ = send_cb_;
    worker_list_.push_back(worker);
  }
  return worker;
}

void CrappySender::Send(std::shared_ptr<CrSession> session) {
  for (auto&& worker : worker_list_) {
    worker->Send(session);
    ++session->response_on_the_way_;
  }
}

void CrappySender::SendTo(std::shared_ptr<CrSession> session,
                          std::shared_ptr<const CrDNSServer> server) {
  std::shared_ptr<CrWorker> worker = nullptr;
  if (worker_map_.find(*server) != worker_map_.end()) {
    worker = worker_map_[*server];
  } else {
    worker = CreateWorker(uv_loop_, server);
    if (worker == nullptr)
      return;
    worker->recv_cb_ = recv_cb_;
    worker->send_cb_ = send_cb_;
    worker_map_.insert({*server, worker});
  }
  worker->Send(session);
}
