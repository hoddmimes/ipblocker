#!/bin/bash
setsid /usr/local/iptblocker/iptblocker.sh > /usr/local/iptblocker/logs/iptblocker-script.log 2>&1 < /dev/null &
ps -eaf | grep iptblock
