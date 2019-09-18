#!/bin/bash
CD=$(date +%F)
cat  /var/log/iptables.log | grep -c -P "${CD} \d+:\d+:\d+ \w+ \w+: Abuse Filter"
