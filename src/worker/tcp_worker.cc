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

#include "tcp_worker.h"

#include <cassert>
#include <iterator>

#include "../session.h"

TCPWorker::TCPWorker(uv_loop_t* uv_loop,
                     std::shared_ptr<const CrDNSServer> server)
    : uv_tcp_(nullptr), recv_buffer_(), query_pool_() {
  uv_loop_ = uv_loop;
  remote_server_ = server;
}

TCPWorker::~TCPWorker() {
  if (uv_tcp_ != nullptr) {
    uv_close((uv_handle_t*)uv_tcp_, [](uv_handle_t* handle) { delete handle; });
  }
}

void TCPWorker::OnInternalRecv(uv_stream_t* handle,
                               ssize_t nread,
                               const uv_buf_t* buf) {
  // Keep callback away from previous connection
  if ((uv_stream_t*)uv_tcp_ != handle)
    return;

  if (nread >= 0) {
    recv_buffer_.insert(recv_buffer_.cend(), buf->base, buf->base + nread);

    while (recv_buffer_.size() >= 2) {
      auto pkt_cur = recv_buffer_.begin();
      uint8_t hi = *pkt_cur++, lo = *pkt_cur++;
      uint16_t pkt_size = (hi << 8) + lo;

      if (recv_buffer_.size() < pkt_size + 2u) {
        break;
      }

      auto pkt_end = std::next(pkt_cur, pkt_size);
      auto pkt = std::make_shared<u8_vec>(pkt_cur, pkt_end);
      auto pkt_id = ntohs(*(uint16_t*)pkt->data());

      if (query_pool_.find(pkt_id) != query_pool_.end()) {
        if (send_cb_)
          send_cb_(pkt_id, remote_server_, 0);
        query_pool_.erase(pkt_id);
        VERB << *remote_server_ << ": Remove session " << pkt_id << " from pool"
             << ENDL;
        if (recv_cb_)
          recv_cb_(CrPacket{.payload = pkt, .dns_server = remote_server_});
      } else {
        WARN << *remote_server_ << ": Can't found session " << pkt_id
             << " in pool, it may caused by a remote double send" << ENDL;
      }
      recv_buffer_.erase(recv_buffer_.begin(), pkt_end);
    }
  } else {
    InternalClose();
  }
}

void TCPWorker::OnInternalConnect(uv_stream_t* handle, int status) {
  if ((uv_stream_t*)uv_tcp_ != handle)
    return;

  if (status == 0) {
    int rtn = uv_read_start(
        (uv_stream_t*)uv_tcp_,
        [](uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
          buf->base = new char[TCP_BUF_SIZE];
          buf->len = TCP_BUF_SIZE;
        },
        [](uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
          ((TCPWorker*)stream->data)->OnInternalRecv(stream, nread, buf);
          delete[] buf->base;
        });
    assert(rtn == 0);
  } else if (status < 0 && status != UV_ECANCELED) {
    InternalClose();
  }
}

int TCPWorker::RequestConnect() {
  uv_tcp_ = new uv_tcp_t;
  uv_tcp_init(uv_loop_, uv_tcp_);
  uv_tcp_nodelay(uv_tcp_, 1);
  uv_tcp_->data = this;

  uv_connect_t* req = new uv_connect_t;
  int rtn = uv_tcp_connect(
      req, uv_tcp_, (const struct sockaddr*)remote_server_->addr.get(),
      [](uv_connect_t* req, int status) {
        auto handle = req->handle;
        ((TCPWorker*)handle->data)->OnInternalConnect(handle, status);
        delete req;
      });

  if (rtn != 0) {
    delete req;
    InternalClose();
  }

  return rtn;
}

void TCPWorker::OnInternalSend(uv_stream_t* handle, int status) {
  if ((uv_stream_t*)uv_tcp_ != handle)
    return;

  if (status < 0 && status != UV_ECANCELED) {
    InternalClose();
  }
}

int TCPWorker::RequestSend(Query* query) {
  uv_buf_t *bufs, *buf_cur;
  unsigned int bufs_count = 0;
  uv_write_t* req = new uv_write_t;

  if (query == nullptr) {
    bufs_count = (unsigned int)query_pool_.size() * 2;
    bufs = buf_cur = new uv_buf_t[bufs_count];
    for (const auto& query_pair : query_pool_) {
      auto& query_item = query_pair.second;
      buf_cur->base = (char*)&query_item.size;
      buf_cur->len = sizeof(uint16_t) / sizeof(char);
      ++buf_cur;
      buf_cur->base = (char*)query_item.request->data();
      buf_cur->len = query_item.request->size();
      ++buf_cur;
    }
  } else {
    bufs_count = 1 * 2;
    bufs = new uv_buf_t[bufs_count];
    bufs[0].base = (char*)&query->size;
    bufs[0].len = sizeof(uint16_t) / sizeof(char);
    bufs[1].base = (char*)query->request->data();
    bufs[1].len = query->request->size();
  }

  int rtn = uv_write(
      req, (uv_stream_t*)uv_tcp_, bufs, bufs_count,
      [](uv_write_t* req, int status) {
        ((TCPWorker*)req->handle->data)->OnInternalSend(req->handle, status);
        delete req;
      });

  if (rtn != 0) {
    delete req;
    InternalClose();
  }

  delete[] bufs;
  return rtn;
}

int TCPWorker::Send(std::shared_ptr<CrSession> session) {
  if (uv_tcp_ == nullptr) {
    int rtn = RequestConnect();
    VERB << *remote_server_ << ": Connect returns " << *(UVError*)&rtn
         << " for session " << session->pipelined_id_ << ENDL;
    if (rtn < 0) {
      return rtn;
    }
  }

  if (query_pool_.find(session->pipelined_id_) != query_pool_.end()) {
    ERR << *remote_server_
        << ": DNS Pipelined ID exist: " << session->pipelined_id_
        << ", query_pool_ size: " << query_pool_.size() << ENDL;

    assert(query_pool_.find(session->pipelined_id_) == query_pool_.end());
  }

  query_pool_[session->pipelined_id_] =
      Query{.retry_count = 0,
            .size = htons(session->request_payload_->size()),
            .request = session->request_payload_};

  return RequestSend(&query_pool_[session->pipelined_id_]);
}

int TCPWorker::InternalClose() {
  uv_close((uv_handle_t*)uv_tcp_, [](uv_handle_t* handle) { delete handle; });
  uv_tcp_ = nullptr;

  recv_buffer_.clear();

  for (auto it = query_pool_.begin(); it != query_pool_.end();) {
    auto& query = it->second;
    if (++query.retry_count > kRetryThreshold) {
      /* TODO: Check SessionManager::Has(it->first) */
      VERB << *remote_server_ << ": Remove session " << it->first
           << " from pool in retry cycle" << ENDL;
      if (send_cb_)
        send_cb_(it->first, remote_server_, UV_ECONNABORTED);
      it = query_pool_.erase(it);
    } else {
      ++it;
    }
  }

  int query_count = (int)query_pool_.size();
  if (query_count > 0) {
    int rtn = RequestConnect();
    VERB << *remote_server_ << ": Pipelined connect returns " << *(UVError*)&rtn
         << " for query queue" << ENDL;
    if (rtn < 0) {
      return rtn;
    }
    rtn = RequestSend(nullptr);
    if (rtn < 0) {
      return rtn;
    }
    return query_count;
  } else {
    query_pool_.clear();
    return 0;
  }
}
