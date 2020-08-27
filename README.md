# ipblocker
Block unwanted connection by scanning mail and http logs for abuse IP address and block these with IPTABLES.

## Overview

I'm running a personal server *(Fedora Server 30)* at home with a Mail, Http and SSHD and a few other services. 
My router is configured to block known abusing host. The host lists are taken from the services listed below
and is updated in the router periodically.

* [Firehole Level 1](http://iplists.firehol.org/?ipset=firehol_level)
* [blocklist.de, the ***all*** list ](http://www.blocklist.de/en/index.html)

In addition the firewall is blocking access from notorious countries that I do not expect any wanted traffic from. 
The country IP ranges are collected and periodically updated from the service [www.ipdeny.com](https://www.ipdeny.com/ipblocks/).
 
 
 This however does not mean that none blocked host couldn't test and abuse the open server.
 Hopefully the server is patched and configured to provide sufficient security. I addition I have deployed 
 this utility ***ipblocker***.
 
 The *ipblocker* is a job running periodically scanning the maillog, http error log 
 and the secure log after abusing entries. The job is running with a relative high frequency, 
 every 8th second.
 
 The job is implemented as bash script [iptblocker.sh](https://github.com/hoddmimes/ipblocker/blob/master/iptblocker.sh).
 The main steps in the script are:
 * Run a Java program [IptableCollector](https://github.com/hoddmimes/ipblocker/blob/master/src/main/java/com/hoddmimes/iptblk/IptableCollector.java) scanning the logfiles that are 
    * /var/log/maillog
    * /var/log/http/xxxxxxxx_error_log
    * /var/log/secure
    
 * The Java program produce a *output file, iptables.cmd* with host that should be blocked or
 unblocker. A host are dynamicaly blocked and unblocked after after a configurable time *(420 minutes)*.
 
 * The ipblocker script parses the *iptables.cmd* outfile and update the [iptables](https://www.howtogeek.com/177621/the-beginners-guide-to-iptables-the-linux-firewall/)
   on the server. 
 
 <sub><sub>*Depending how you have configured you system/services the logfile may have other names and locations. The services 
 logfiles can however be passed as parameters to the java program IptableCollector*</sub></sub>
 
 
 ### Script Files
 
 * [spawnIptblockScript.sh](https://github.com/hoddmimes/ipblocker/blob/master/spawnIptblockScript.sh) kick off the 
 ipblocker script as a detached backgroup job.
 
 * [iptblocker.sh](https://github.com/hoddmimes/ipblocker/blob/master/iptblocker.sh) script priodically scanning and 
 updating the iptables on the server.
 
 * [resetIptables.sh](https://github.com/hoddmimes/ipblocker/blob/master/resetIptables.sh) remove iptables chain and 
 re-define iptable chains needed by the *iptblocker* script.
 

### Timestamps in Service Logfiles

In my case the timestamp notation was not unified among the different services so I have aligned the ones that are 
using the syslog facility to use the format "yyyy-MM-dd HH:mm:ss". It is also the format I prefer.

This is acomplish by configuring the /etc/rsyslog.config

- Add a timeformat definition to the file 
    - $template VanilaLogFormat, "%timestamp:::date-year%-%timestamp:::date-month%-%timestamp:::date-day% %timestamp:::date-hour%:%timestamp:::date-minute
      %:%timestamp:::date-second% %hostname% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"

- Update the various services in the  /etc/rsyslog.config to use the defined time format e.g
    - mail.*                                                  /var/log/maillog;VanilaLogFormat
    - authpriv.*                                              /var/log/secure;VanilaLogFormat
    
    
My HTTP server is Apachache and to align the timeformat I had to change the **httpd.conf** file in the following way

- Define a logtime format 

>>\<IfModule log_config_module\>
    \#                                                                                                                                               
    \# The following directives define some format nicknames for use with                                                                            
    \# a CustomLog directive (see below).                                                                                                            
    \#                                                                                                                                               
    LogFormat "%h %l %u  %{%Y-%m-%d %H:%M:%S}t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %{%Y-%m-%d %H:%M:%S}t \"%r\" %>s %b" common


>>  \<IfModule logio_module\>

>>>\# You need to enable mod_logio.c to use %I and %O                                                                                             
     LogFormat "%h %l %u %{%Y-%m-%d %H:%M:%S}t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
    \</IfModule\>


 
 - For the logfiles add the format, under each virtual server e.g
    - *CustomLog logs/hoddmimes_access_log common env=!dontlog*
    
    
  ### IPTABLES
  
  Information about *iptables* on server is the mechanism blocking host to connect. Information about *iptables* can be found
  [here](https://www.booleanworld.com/depth-guide-iptables-linux-firewall/).
  
  To see what blocking filter that are in place and how many connection that has been blocked can be obtained with the following comand 
  
  <code>
  $ iptables -L -v -n 
  </code> 

 
 