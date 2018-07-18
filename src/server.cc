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

#include "server.h"

#include "session.h"

static void alloc_buffer(uv_handle_t* handle,
                         size_t suggested_size,
                         uv_buf_t* buf) {
  buf->base = new char[UDP_BUF_SIZE];
  buf->len = UDP_BUF_SIZE;
}

static void send_cb(uv_udp_send_t* req, int status) {
  CrappyServer* self = (CrappyServer*)((uv_req_t*)req)->data;
  if (self->send_cb_)
    self->send_cb_(status);
  delete req;
}

static void close_cb(uv_handle_t* handle) {
  CrappyServer* self = (CrappyServer*)handle->data;
  delete handle;
  if (self->close_cb_)
    self->close_cb_();
}

static void recv_cb(uv_udp_t* handle,
                    ssize_t nread,
                    const uv_buf_t* buf,
                    const struct sockaddr* addr,
                    unsigned flags) {
  CrappyServer* self = (CrappyServer*)handle->data;
  if (nread >= 0 && addr != nullptr) {
    auto payload = std::make_shared<u8_vec>(buf->base, buf->base + nread);
    auto addr_ptr = std::make_shared<struct sockaddr_storage>();
    ::memcpy(addr_ptr.get(), addr, get_sockaddr_size(addr));
    if (self->recv_cb_)
      self->recv_cb_(CrPacket{
          .payload = payload, .dns_server = nullptr, .addr = addr_ptr});
  } else if (nread != 0) {
    self->Close();
  }
  delete[] buf->base;
}

CrappyServer::CrappyServer(uv_loop_t* uv_loop)
    : close_cb_(nullptr), send_cb_(nullptr), recv_cb_(nullptr) {
  uv_udp_ = new uv_udp_t;
  uv_udp_init(uv_loop, uv_udp_);
  uv_udp_->data = this;
}

CrappyServer::~CrappyServer() {
  if (uv_udp_ != nullptr) {
    uv_close((uv_handle_t*)uv_udp_, [](uv_handle_t* handle) { delete handle; });
  }
}

int CrappyServer::Serve(const struct sockaddr* addr, unsigned int flags) {
  int rtn = uv_udp_bind(uv_udp_, addr, flags);
  if (rtn < 0)
    return rtn;
  return uv_udp_recv_start(uv_udp_, &alloc_buffer, &recv_cb);
}

int CrappyServer::Send(std::shared_ptr<const CrSession> session) {
  uv_udp_send_t* req = new uv_udp_send_t;
  ((uv_req_t*)req)->data = this;
  uv_buf_t buf = uv_buf_init((char*)session->candidate_response_->data(),
                             (uint)session->candidate_response_->size());
  int rtn =
      uv_udp_send(req, uv_udp_, &buf, 1,
                  (const struct sockaddr*)session->reply_to_.get(), &send_cb);

  if (rtn != 0) {
    delete req;
    Close();
  }

  return rtn;
}

int CrappyServer::Shutdown() {
  return uv_udp_recv_stop(uv_udp_);
}

void CrappyServer::Close() {
  if (uv_udp_ != nullptr) {
    uv_close((uv_handle_t*)uv_udp_, &close_cb);
    uv_udp_ = nullptr;
  }
}
