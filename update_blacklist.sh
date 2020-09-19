#!/bin/bash
#
NETGROUP="BLACKLIST_DROP"
NEWGROUP=${NETGROUP}-$$
#LOGFILE=/config/scripts/post-config.d/blacklist.log
LOGFILE=/dev/stdout
TMP_FILE=/tmp/blacklist
TMP_FILE_X=${TMP_FILE}tmp
#
#
#
LOGTIME=`date +"%Y-%m-%d %T"`
sudo echo "$LOGTIME Start updating $NETGROUP" >> $LOGFILE
curl -s -insecure https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset | grep '^[0-9]' | sed -e "s/^/-A $NEWGROUP /" > $TMP_FILE_X
curl -s -G https://api.abuseipdb.com/api/v2/blacklist   -d confidenceMinimum=90 -H "Key: c776abda35d229fc4f70379d7cd0ab9dee6f68421f96fd2f3bd872ea9354e6f6cb85aaf0590824b5" \
   -H "Accept: text/plain" grep '^[0-9]' | sed -e "s/^/-A $NEWGROUP /" >> $TMP_FILE_X
sort $TMP_FILE_X | uniq -u > $TMP_FILE
rm -f $TMP_FILE_X
#
sudo ipset -q -L $NETGROUP > /dev/null 2>&1 
if [ "$?" != 0 ]; then        
  echo "$LOGTIME firewall network group $NETGROUP doesn't exist yet" >> $LOGFILE
  exit 1 
fi  
#
sudo ipset create $NEWGROUP hash:net 
if [ "$?" != 0 ]; then       
  echo "$LOGTIME There was an error trying to create temporary set" >> $LOGFILE   
  exit 1 
fi
# echo "created temporary $NEWGROUP"
#
#
sudo ipset -! -R < $TMP_FILE
if [ "$?" != 0 ]; then        
  LOGTIME=`date +"%Y-%m-%d %T"`
  echo "$LOGTIME failed to update $NEWGROUP" >> $LOGFILE
  exit 1 
fi  
# 
sudo ipset swap $NEWGROUP $NETGROUP 
if [ "$?" != 0 ]; then       
   echo "$LOGTIME There was an error trying to swap temporary set" >> $LOGFILE
   exit 1 
fi 
COUNT=$(wc -l $TMP_FILE)
sudo ipset destroy $NEWGROUP 
rm -f $TMP_FILE 
LOGTIME=`date +"%Y-%m-%d %T"`
sudo echo "$LOGTIME Added $COUNT entries to $NETGROUP" >> $LOGFILE 
exit 0

