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

#include "udp_worker.h"

#include "../session.h"

UDPWorker::UDPWorker(uv_loop_t* uv_loop,
                     std::shared_ptr<const CrDNSServer> server)
    : uv_udp_(nullptr) {
  uv_loop_ = uv_loop;
  remote_server_ = server;
}

UDPWorker::~UDPWorker() {
  if (uv_udp_ != nullptr) {
    uv_close((uv_handle_t*)uv_udp_, [](uv_handle_t* handle) { delete handle; });
  }
}

void UDPWorker::OnInternalSend(uv_udp_send_t* req, int status) {
  if (req->handle != uv_udp_)
    return;
  if (status != 0 && status != UV_ECANCELED) {
    InternalClose();
  }

  auto query = (Query*)req->data;
  if (send_cb_)
    send_cb_(query->id, remote_server_, status);
}

int UDPWorker::Send(std::shared_ptr<CrSession> session) {
  if (uv_udp_ == nullptr) {
    Restart();
  }

  uv_udp_send_t* req = new uv_udp_send_t;
  req->data = new Query{.id = session->pipelined_id_,
                        .request = session->request_payload_};
  uv_buf_t buf = uv_buf_init((char*)session->request_payload_->data(),
                             (uint)session->request_payload_->size());
  int rtn = uv_udp_send(
      req, uv_udp_, &buf, 1, (const struct sockaddr*)remote_server_->addr.get(),
      [](uv_udp_send_t* req, int status) {
        ((UDPWorker*)req->handle->data)->OnInternalSend(req, status);
        delete (Query*)req->data;
        delete req;
      });

  if (rtn != 0) {
    if (send_cb_)
      send_cb_(session->pipelined_id_, remote_server_, rtn);
    delete (Query*)req->data;
    delete req;
    InternalClose();
  }

  return rtn;
}

void UDPWorker::OnInternalRecv(uv_udp_t* handle,
                               ssize_t nread,
                               const uv_buf_t* buf,
                               const struct sockaddr* addr,
                               unsigned flags) {
  if (handle != uv_udp_)
    return;
  if ((flags & UV_UDP_PARTIAL) != 0) {
    VERB << "Met UV_UDP_PARTIAL" << ENDL;
    return;
  }

  auto remote_addr = (const struct sockaddr*)remote_server_->addr.get();
  if (nread >= 0 && addr != nullptr && cmp_sockaddr(remote_addr, addr) == 0) {
    if (recv_cb_) {
      auto pkt = std::make_shared<u8_vec>(buf->base, buf->base + nread);
      recv_cb_({.payload = pkt, .dns_server = remote_server_});
    }
  } else if (nread != 0) {
    InternalClose();
  }
}

int UDPWorker::Restart() {
  uv_udp_ = new uv_udp_t;
  uv_udp_init(uv_loop_, uv_udp_);
  uv_udp_->data = this;
  return uv_udp_recv_start(
      uv_udp_,
      [](uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
        buf->base = new char[UDP_BUF_SIZE];
        buf->len = UDP_BUF_SIZE;
      },
      [](uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
         const struct sockaddr* addr, unsigned flags) {
        ((UDPWorker*)handle->data)
            ->OnInternalRecv(handle, nread, buf, addr, flags);
        delete[] buf->base;
      });
}

int UDPWorker::InternalClose() {
  uv_close((uv_handle_t*)uv_udp_, [](uv_handle_t* handle) { delete handle; });
  uv_udp_ = nullptr;
  return 0;
}
