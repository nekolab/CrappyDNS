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

#ifndef _CR_SERVER_H_
#define _CR_SERVER_H_

#include <functional>

#include "crappydns.h"

class CrSession;

class CrappyServer {
 public:
  CrappyServer(uv_loop_t* uv_loop);
  ~CrappyServer();

  std::function<void()> close_cb_;
  std::function<void(int)> send_cb_;
  std::function<void(CrPacket)> recv_cb_;

  int Serve(const struct sockaddr* addr, unsigned int flags);
  int Send(std::shared_ptr<const CrSession> session);
  int Shutdown();
  void Close();

 private:
  uv_udp_t* uv_udp_;
};

#endif
