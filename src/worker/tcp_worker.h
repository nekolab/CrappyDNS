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

#ifndef _CR_TCP_WORKER_H_
#define _CR_TCP_WORKER_H_

#include "worker.h"

#include <list>
#include <unordered_map>

class TCPWorker : public CrWorker {
 public:
  TCPWorker(uv_loop_t* uv_loop, std::shared_ptr<const CrDNSServer> server);
  ~TCPWorker();

  int Send(std::shared_ptr<CrSession> session);

  void OnInternalConnect(uv_stream_t* handle, int status);
  void OnInternalSend(uv_stream_t* handle, int status);
  void OnInternalRecv(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);

 private:
  const static uint8_t kRetryThreshold = 1;

  struct Query {
    uint8_t retry_count;
    uint16_t size;
    std::shared_ptr<const u8_vec> request;
  };

  uv_tcp_t* uv_tcp_;
  std::list<uint8_t> recv_buffer_;
  std::unordered_map<uint16_t, Query> query_pool_;

  int RequestSend(Query* query);
  int RequestConnect();
  int InternalClose();
};

#endif
