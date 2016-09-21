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

#ifndef _CR_SENDER_H_
#define _CR_SENDER_H_

#include <functional>
#include <list>
#include <unordered_map>

#include "crappydns.h"

class CrSession;
class CrWorker;

class CrappySender {
 public:
  CrappySender(uv_loop_t* uv_loop)
      : recv_cb_(nullptr),
        send_cb_(nullptr),
        uv_loop_(uv_loop),
        worker_list_(),
        worker_map_() {}
  ~CrappySender() {}

  std::function<void(CrPacket)> recv_cb_;
  std::function<void(uint16_t, std::shared_ptr<const CrDNSServer>, int)>
      send_cb_;

  std::shared_ptr<CrWorker> RegisterDNSServer(
      std::shared_ptr<const CrDNSServer> server);
  void Send(std::shared_ptr<CrSession> session);
  void SendTo(std::shared_ptr<CrSession> session,
              std::shared_ptr<const CrDNSServer> server);

 private:
  uv_loop_t* uv_loop_;
  std::list<std::shared_ptr<CrWorker>> worker_list_;
  std::unordered_map<CrDNSServer, std::shared_ptr<CrWorker>> worker_map_;
};

#endif
