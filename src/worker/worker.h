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

#ifndef _CR_WORKER_H_
#define _CR_WORKER_H_

#include <functional>

#include "../crappydns.h"

class CrSession;

class CrWorker {
 public:
  virtual ~CrWorker(){};

  std::function<void(uint16_t, std::shared_ptr<const CrDNSServer>, int)>
      send_cb_;
  std::function<void(CrPacket)> recv_cb_;

  virtual int Send(std::shared_ptr<CrSession> session) = 0;

 protected:
  uv_loop_t* uv_loop_;
  std::shared_ptr<const CrDNSServer> remote_server_;
};

#endif
