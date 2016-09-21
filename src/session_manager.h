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

#ifndef _CR_SESSION_MANAGER_H_
#define _CR_SESSION_MANAGER_H_

#include <random>
#include <unordered_map>

#include "crappydns.h"
#include "sender.h"

class CrSession;
class CrappyServer;

class CrSessionManager {
 public:
  CrSessionManager(uv_loop_t* loop, CrappyServer* server);
  ~CrSessionManager(){};

  std::shared_ptr<CrSession> Create(CrPacket packet);
  std::shared_ptr<CrSession> Get(uint16_t pipelined_id);
  bool Has(uint16_t pipelined_id);
  void Destory(uint16_t pipelined_id);

  bool Dispatch(uint16_t pipelined_id);
  void OnRemoteRecv(CrPacket response);
  void Resolve(uint16_t pipelined_id);

  uint16_t GenPipelinedID();

 private:
  // shuffle times for uint16_t
  static const uint8_t kShuffleTimes = 16 - 1;

  uint64_t timeout_;
  uv_loop_t* uv_loop_;
  CrappySender sender_;
  CrappyServer* server_;

  uint16_t counter_;
  std::minstd_rand mr_step_;
  uint8_t shuffle_seq_[kShuffleTimes];

  std::unordered_map<uint16_t, std::shared_ptr<CrSession>> pool_;

  void PrepareServer();
  void PrepareSender();
  void GenShuffleSequence(uint_fast32_t seed);
};

#endif
