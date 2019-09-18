#!/bin/bash
cd /usr/local/iptblocker
java -cp ./libs/iptblk-1.0.jar:./libs/gson-2.8.5.jar com.hoddmimes.iptblk.IptableCollector -reset $1 \
     -blacklistTime 420 \
     -cmdfile ./iptables.cmd \
     -allowLocalAddr 192.168.42 \
     -outDir ./logs/ \
     -verbose false \
     -maillog /var/log/maillog \
     -httplog /var/log/httpd/hoddmimes_error_log
exit
