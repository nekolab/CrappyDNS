#!/bin/sh

curl 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | grep ipv4 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, 32-log($5)/log(2)) }' > chnroute.txt

if command -v crappydns >/dev/null 2>&1; then
  crappydns -o chnroute.txt > chnroute.tmp
  mv chnroute.tmp chnroute.txt
elif [ -f "src/crappydns" ]; then
  src/crappydns -o chnroute.txt > chnroute.tmp
  mv chnroute.tmp chnroute.txt
fi
