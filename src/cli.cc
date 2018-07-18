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

#include "crappydns.h"

#include <getopt.h>
#include <cstdlib>

#include "hosts/hosts.h"
#include "server.h"
#include "session.h"
#include "session_manager.h"
#include "trusted_net.h"

void PrintHelpMessage() {
  printf("CrappyDNS %s\n", VERSION);
  // clang-format off
  printf(
    "Usage: crappydns [-l LISTEN_ADDR] [-p LISTEN_PORT] [-t TIMEOUT_IN_MS]\n"
    "         [-b POISONED_DNS_LIST] [-g HEALTHY_DNS_LIST] [-v] [-V] [-h]\n"
    "         [-n TRUSTED_NET_PATH] [-o TRUSTED_NET_PATH]\n"
    "A crappy DNS repeater\n"
    "\n"
    "Options:\n"
    "-g, --good-dns <dns>\tComma seperated healthy remote DNS server list,\n"
    "\t\t\tDNS address schema: [(udp|tcp)://]i.p.v.4[:port]\n"
    "\t\t\tProctol default to udp, port default to 53\n"
    "-b, --bad-dns <dns>\tComma seperated poisoned remote DNS server list.\n"
    "-s, --hosts <file>\tPath to hosts file\n"
    "-n, --trusted-net <file>Path to the file contains trusted net list\n"
    "-o, --optimize <file>\tOptimize trusted net list, write to stdout and exit\n"
    "[-p, --port <port>]\tPort number of your local server, default to 53\n"
    "[-l, --listen <addr>]\tListen address of your local server,\n"
    "\t\t\tdefault to 127.0.0.1\n"
    "[-t, --timeout <msec>]\tTimeout for each session, default to 3000\n"
    "[-v, --version]\t\tPrint version and exit\n"
    "[-V, --verbose]\t\tVerbose logging\n"
    "[-h, --help]\t\tPrint this message\n");
  // clang-format on
}

bool ValidateConfig() {
  return !CrConfig::dns_list.empty();
}

char ParseConfig(int argc, char** argv) {
  uint16_t listen_port = 53;
  const char* listen_addr = "127.0.0.1";

  opterr = 0;
  int c = 0;
  int option_index = 0;
  struct option long_options[] = {
      {"port", required_argument, nullptr, 'p'},
      {"bad-dns", required_argument, nullptr, 'b'},
      {"good-dns", required_argument, nullptr, 'g'},
      {"trusted-net", required_argument, nullptr, 'n'},
      {"hosts", required_argument, nullptr, 's'},
      {"optimize", required_argument, nullptr, 'o'},
      {"listen", required_argument, nullptr, 'l'},
      {"timeout", required_argument, nullptr, 't'},
      {"version", no_argument, nullptr, 'v'},
      {"verbose", no_argument, nullptr, 'V'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, no_argument, nullptr, 0}};

  while ((c = getopt_long(argc, argv, "p:b:g:n:s:o:l:t:vVh", long_options,
                          &option_index)) != -1) {
    switch (c) {
      case 'o':
        if (CrConfig::trusted_net.LoadFile(optarg, false) != 0) {
          exit(-4);
        }
        CrConfig::trusted_net.PrintRouteTable();
        exit(0);
        break;
      case 'p':
        listen_port = strtol(optarg, nullptr, 0);
        if (listen_port == 0) {
          return c;
        }
        break;
      case 'b':
        if (!ParseDNSList(optarg, CrDNSServer::Health::kPoisoned,
                          CrConfig::dns_list)) {
          return c;
        }
        break;
      case 'g':
        if (!ParseDNSList(optarg, CrDNSServer::Health::kHealthy,
                          CrConfig::dns_list)) {
          return c;
        }
        break;
      case 'n':
        if (CrConfig::trusted_net.LoadFile(optarg) != 0) {
          ERR << "Failed to open " << optarg << ENDL;
          exit(-3);
        }
        break;
      case 's':
        if (CrConfig::hosts.LoadFile(optarg) != 0) {
          ERR << "Failed to open " << optarg << ENDL;
          exit(-4);
        }
        break;
      case 'l':
        listen_addr = optarg;
        break;
      case 't':
        CrConfig::timeout_in_ms = strtol(optarg, nullptr, 0);
        if (CrConfig::timeout_in_ms == 0) {
          return c;
        }
        break;
      case 'v':
        printf("CrappyDNS %s\n", VERSION);
        exit(0);
        break;
      case 'V':
        CrConfig::verbose_mode = true;
        break;
      case 'h':
      default:
        PrintHelpMessage();
        exit(0);
    }
  }

  auto cfg_addr_v4 = (struct sockaddr_in*)&CrConfig::listen_addr;
  auto cfg_addr_v6 = (struct sockaddr_in6*)&CrConfig::listen_addr;
  if (UV_EINVAL == uv_ip4_addr(listen_addr, listen_port, cfg_addr_v4) &&
      UV_EINVAL == uv_ip6_addr(listen_addr, listen_port, cfg_addr_v6)) {
    return 'l';
  }

  return 0;
}

int main(int argc, char** argv) {
  uv_loop_t* uv_loop;

  if (ParseConfig(argc, argv) != 0) {
    PrintHelpMessage();
    return -1;
  }

  if (!ValidateConfig()) {
    PrintHelpMessage();
    return -2;
  }

  uv_loop = uv_default_loop();
  CrappyServer server(uv_loop);
  CrSessionManager manager(uv_loop, &server);

  int rtn = server.Serve((const struct sockaddr*)&CrConfig::listen_addr, 0);
  if (rtn != 0) {
    return rtn;
  }

  INFO << "Listening at " << *(SockAddr*)&CrConfig::listen_addr << ENDL;

  uv_run(uv_loop, UV_RUN_DEFAULT);
  uv_loop_close(uv_loop);
  return 0;
}
