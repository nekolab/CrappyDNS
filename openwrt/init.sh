#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

LISTEN=127.0.0.1
PORT=5353
TIMEOUT=1500
HOSTS=/etc/crappyhosts
TRUSTED_NET=/etc/chnroute.txt
GOOD_DNS=tcp://8.8.4.4,tcp://8.8.8.8
BAD_DNS=114.114.114.114,202.96.209.133

start_service() {
	procd_open_instance
	procd_set_param command /usr/bin/crappydns -l $LISTEN -p $PORT -g $GOOD_DNS -b $BAD_DNS -n $TRUSTED_NET -s $HOSTS -t $TIMEOUT
	procd_set_param limits nofile=51200
	procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param file $HOSTS
	procd_set_param file $TRUSTED_NET
	procd_close_instance
}
