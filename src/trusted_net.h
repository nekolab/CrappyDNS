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

#ifndef _CR_TRUSTED_NET_H_
#define _CR_TRUSTED_NET_H_

#include <memory>
#include <vector>

class CrTrustedNet {
 public:
  CrTrustedNet() : route_table_(){};
  ~CrTrustedNet(){};

  struct RouteEntry {
    uint32_t segment;
    uint8_t mask;
  };

  int LoadFile(const char* path, bool with_reserved = true);
  bool Contains(uint32_t ip_addr) const;
  void PrintRouteTable() const;

 private:
  struct TreeNode {
    bool is_leaf_node;
    std::shared_ptr<TreeNode> zero;
    std::shared_ptr<TreeNode> one;
  };

  std::vector<RouteEntry> route_table_;

  static void AddLeaf(std::shared_ptr<TreeNode> nod, uint32_t seg, uint8_t msk);
  static void ShirnkTree(std::shared_ptr<TreeNode> root);

  void PickLeaf(std::shared_ptr<TreeNode> root, uint32_t segment, uint8_t mask);
};

#endif
