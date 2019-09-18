#!/bin/bash
IPTABLES=/usr/sbin/iptables                       # Where the iptables exec is located
BLACKLIST=./logs/iptable.cmd                      # Black list file to process
#
${IPTABLES} --flush
${IPTABLES} --delete-chain
${IPTABLES} -P INPUT ACCEPT
${IPTABLES} -P FORWARD ACCEPT
${IPTABLES} -P OUTPUT ACCEPT
${IPTABLES} -I OUTPUT -m state --state NEW -j LOG --log-prefix "New OUT connection: "
#
${IPTABLES} -N ABUSE
${IPTABLES} -A ABUSE -j LOG --log-level 6 --log-prefix "Abuse Filter Drop: "
${IPTABLES} -A ABUSE -j DROP
#
#
rm -v "${BLACKLIST}"
#
