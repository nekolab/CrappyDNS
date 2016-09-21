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

#ifndef _CR_UDP_WORKER_H_
#define _CR_UDP_WORKER_H_

#include "worker.h"

class UDPWorker : public CrWorker {
 public:
  UDPWorker(uv_loop_t* uv_loop, std::shared_ptr<const CrDNSServer> server);
  ~UDPWorker();

  int Send(std::shared_ptr<CrSession> session);
  void OnInternalSend(uv_udp_send_t* req, int status);
  void OnInternalRecv(uv_udp_t* handle,
                      ssize_t nread,
                      const uv_buf_t* buf,
                      const struct sockaddr* addr,
                      unsigned flags);

 private:
  struct Query {
    uint16_t id;
    std::shared_ptr<const u8_vec> request;
  };

  uv_udp_t* uv_udp_;
  int Restart();
  int InternalClose();
};

#endif
