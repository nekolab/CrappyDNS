CrappyDNS
=========

CrappyDNS is a DNS repeater based on [libuv][libuv], written in C++11,
provides enhanced DNS resolution.

How it works
------------
To use CrappyDNS, you need to provide a healthy DNS server list,
a polluted DNS server list and a trusted net list.

Each DNS server list is a comma separated ip list, support optional
`tcp://` prefix to issue a TCP connection and `:port` suffix to connect
to different port number other than the default port 53.

The trusted net list is a [CIDR blocks][cidr-blocks] list, with one
CIDR blocks per line. In many cases, the CIDR blocks list may contains
tons of duplicated or mergeable items, so CrappyDNS provides `-o` options
to merge them as it possible.

For each DNS query, CrappyDNS will forward it to each DNS server in
two lists. CrappyDNS prefer to use the result returned by polluted DNS
server when the result is in trusted net list, and in opposite, it will
prefer to use the result returned by healthy DNS server when the result
is not in trusted net list.

CrappyDNS also supports an enhanced `hosts` file format, which enables
you to designate a special DNS server (or resolution result) for specific
domain, you may refer to [`hosts`][hosts] file in this repo to see more details.

Build
-----
### Linux / Unix

You should have [libuv][libuv] installed first, then
```
$ ./autogen.sh
$ ./configure
$ make
```

### OpenWrt

1. Follow the [instruction][openwrt-sdk] to install OpenWrt SDK
2. Clone this repo into `package` folder under SDK root directory
3. Run `make menuconfig` under SDK root directory and select `Network/crappydns`
4. Run `make` to start build process

Usage
-----
```
crappydns [-l LISTEN_ADDR] [-p LISTEN_PORT] [-t TIMEOUT_IN_MS]
          [-b POISONED_DNS_LIST] [-g HEALTHY_DNS_LIST] [-v] [-V] [-h]
          [-n TRUSTED_NET_PATH] [-o TRUSTED_NET_PATH] [-a USER]
A crappy DNS repeater

Options:
-g, --good-dns <dns>	 Comma seperated healthy remote DNS server list,
			 DNS address schema: [(udp|tcp)://]i.p.v.4[:port]
			 Proctol default to udp, port default to 53
-b, --bad-dns <dns>	 Comma seperated poisoned remote DNS server list.
-s, --hosts <file>	 Path to hosts file
-n, --trusted-net <file> Path to the file contains trusted net list
-o, --optimize <file>	 Optimize trusted net list, write to stdout and exit
[-p, --port <port>]	 Port number of your local server, default to 53
[-l, --listen <addr>]	 Listen address of your local server,
			 default to 127.0.0.1
[-t, --timeout <msec>]	 Timeout for each session, default to 3000
[-a, --run-as <user>]	 Run as another user
[-v, --version]		 Print version and exit
[-V, --verbose]		 Verbose logging
[-h, --help]		 Print this message
```

License
-------
![GPLv3](https://www.gnu.org/graphics/gplv3-127x51.png)

CrappyDNS is licensed under [GNU General Public License][gpl] Version 3.

Copyright (C) 2019  Sunny

CrappyDNS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CrappyDNS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <[http://www.gnu.org/licenses/][gpl-licenses]>.


[libuv]: https://libuv.org/
[cidr-blocks]: https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_blocks
[openwrt-sdk]: https://openwrt.org/docs/guide-developer/using_the_sdk
[hosts]: https://github.com/nekolab/CrappyDNS/blob/master/hosts
[gpl]: https://www.gnu.org/licenses/gpl.html
[gpl-licenses]: http://www.gnu.org/licenses/
