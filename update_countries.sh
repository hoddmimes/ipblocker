#!/bin/bash
declare -A COUNTRIES
COUNTRIES[cn]=CHINA
COUNTRIES[br]=BRAZIL
COUNTRIES[ru]=RUSSIA
COUNTRIES[ua]=UKRAINE

LOGFILE=/config/scripts/post-config.d/countries.log
LOGFILE=/dev/stdout
NETGROUP=COUNTRIES_DROP
NETGROUPTMP=${NETGROUP}-$$
TMP_FILE=/tmp/countrieslist
TMP_FILE_X=${TMP_FILE}tmp

rm -f $TMP_FILE_X
for COUNTRY_CODE in ${!COUNTRIES[@]}
do
    COUNTRY_NAME=${COUNTRIES[$COUNTRY_CODE]}
    LOGTIME=`date +"%Y-%m-%d %T"`
    sudo echo "$LOGTIME start retreving IP blocks for $COUNTRY_NAME" >> $LOGFILE
    curl -s --insecure https://www.ipdeny.com/ipblocks/data/countries/$COUNTRY_CODE.zone | grep '^[0-9]' | sed -e "s/^/-A $NETGROUPTMP /" >> $TMP_FILE_X
    LOGTIME=`date +"%Y-%m-%d %T"`
    sudo echo "$LOGTIME Loaded IP blocks for $COUNTRY_NAME" >> $LOGFILE
done
    
sort $TMP_FILE_X | uniq -u > $TMP_FILE
rm -f $TMP_FILE_X
    
#
sudo ipset -q -L $NETGROUP > /dev/null 2>&1 
if [ "$?" != 0 ]; then        
  LOGTIME=`date +"%Y-%m-%d %T"`
  echo "$LOGTIME firewall network group $NETGROUP doesn't exist yet" >> $LOGFILE
  exit 1 
fi  
    
#
sudo ipset create $NETGROUPTMP hash:net  hashsize 65535 resize 2000 probes 4
if [ "$?" != 0 ]; then       
  LOGTIME=`date +"%Y-%m-%d %T"`
  echo "$LOGTIME There was an error trying to create temporary set" >> $LOGFILE   
  exit 1 
fi
#
sudo ipset -! -R < $TMP_FILE
if [ "$?" != 0 ]; then        
  LOGTIME=`date +"%Y-%m-%d %T"`
  echo "$LOGTIME failed to update $NETGROUPTMP" >> $LOGFILE
  exit 1 
fi  
#
sudo ipset swap $NETGROUPTMP $NETGROUP 
if [ "$?" != 0 ]; then       
  LOGTIME=`date +"%Y-%m-%d %T"`
  echo "$LOGTIME There was an error trying to swap temporary set" >> $LOGFILE
  exit 1 
fi 
COUNT=$(wc -l $TMP_FILE)
sudo ipset destroy $NETGROUPTMP
rm -f $TMP_FILE
LOGTIME=`date +"%Y-%m-%d %T"`
echo "$LOGTIME Added $COUNT entries to $NETGROUP" >> $LOGFILE 
#
LOGTIME=`date +"%Y-%m-%d %T"`
sudo echo "$LOGTIME All done for this time, folks" >> $LOGFILE 
exit 0

