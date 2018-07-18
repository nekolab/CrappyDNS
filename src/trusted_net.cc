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

#include "trusted_net.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>

#include <arpa/inet.h>

static bool cmp_route(const CrTrustedNet::RouteEntry& lhs,
                      const CrTrustedNet::RouteEntry& rhs) {
  uint8_t shift = 32 - std::min(lhs.mask, rhs.mask);
  return (lhs.segment >> shift) < (rhs.segment >> shift);
}

int CrTrustedNet::LoadFile(const char* path, bool with_reserved) {
  std::string line;
  std::ifstream ifs(path);
  std::shared_ptr<TreeNode> root = std::make_shared<TreeNode>(TreeNode{});

  if (!ifs)
    return -1;

  if (with_reserved) {
    // Add reserved IP address
    // See https://en.wikipedia.org/wiki/Reserved_IP_addresses
    AddLeaf(root, 0x00000000, 8);   // 0.0.0.0/8
    AddLeaf(root, 0x0a000000, 8);   // 10.0.0.0/8
    AddLeaf(root, 0x64400000, 10);  // 100.64.0.0/10
    AddLeaf(root, 0x7f000000, 8);   // 127.0.0.0/8
    AddLeaf(root, 0xa9fe0000, 16);  // 169.254.0.0/16
    AddLeaf(root, 0xac100000, 12);  // 172.16.0.0/12
    AddLeaf(root, 0xc0000000, 24);  // 192.0.0.0/24
    AddLeaf(root, 0xc0000200, 24);  // 192.0.2.0/24
    AddLeaf(root, 0xc0586300, 24);  // 192.88.99.0/24
    AddLeaf(root, 0xc0a80000, 16);  // 192.168.0.0/16
    AddLeaf(root, 0xc6120000, 15);  // 198.18.0.0/15
    AddLeaf(root, 0xc6336400, 24);  // 198.51.100.0/24
    AddLeaf(root, 0xcb007100, 24);  // 203.0.113.0/24
    AddLeaf(root, 0xe0000000, 4);   // 224.0.0.0/4
    // AddLeaf(root, 0xf0000000, 4);   // 240.0.0.0/4
    AddLeaf(root, 0xffffffff, 32);  // 255.255.255.255/32
  }

  while (std::getline(ifs, line)) {
    uint8_t segment[4], mask = 32;
    int rtn = sscanf(line.data(), "%hhu.%hhu.%hhu.%hhu/%hhu", &segment[0],
                     &segment[1], &segment[2], &segment[3], &mask);
    if (rtn == 4 || rtn == 5) {
      AddLeaf(root, ntohl(*(uint32_t*)segment), mask);
    }
  }
  ifs.close();

  ShirnkTree(root);
  PickLeaf(root, 0, 0);
  route_table_.shrink_to_fit();

  return 0;
}

bool CrTrustedNet::Contains(uint32_t ip_addr) const {
  return std::binary_search(route_table_.begin(), route_table_.end(),
                            RouteEntry{.segment = ip_addr, .mask = 32},
                            &cmp_route);
}

void CrTrustedNet::PrintRouteTable() const {
  for (const auto& entry : route_table_) {
    uint32_t segment = htonl(entry.segment);
    uint8_t* const seg = (uint8_t*)&segment;
    printf("%hhu.%hhu.%hhu.%hhu/%hhu\n", *seg, *(seg + 1), *(seg + 2),
           *(seg + 3), entry.mask);
  }
}

void CrTrustedNet::AddLeaf(std::shared_ptr<TreeNode> node,
                           uint32_t segment,
                           uint8_t mask) {
  node->is_leaf_node = node->is_leaf_node || mask == 0;
  if (node->is_leaf_node)
    return;

  auto& child = (segment >> 31) ? node->one : node->zero;
  if (!child)
    child = std::make_shared<TreeNode>(TreeNode{});
  return AddLeaf(child, segment << 1, mask - 1);
}

void CrTrustedNet::ShirnkTree(std::shared_ptr<TreeNode> root) {
  if (!root || root->is_leaf_node)
    return;
  ShirnkTree(root->zero);
  ShirnkTree(root->one);
  if (root->zero && root->one && root->zero->is_leaf_node &&
      root->one->is_leaf_node) {
    root->is_leaf_node = true;
  }
}

void CrTrustedNet::PickLeaf(std::shared_ptr<TreeNode> root,
                            uint32_t segment,
                            uint8_t mask) {
  if (!root)
    return;
  if (root->is_leaf_node) {
    assert(mask > 0 && mask <= 32);
    route_table_.push_back({.segment = segment << (32 - mask), .mask = mask});
    return;
  }

  PickLeaf(root->zero, segment << 1, mask + 1);
  PickLeaf(root->one, (segment << 1) | 0x1, mask + 1);
}
