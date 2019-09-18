#!/bin/bash
#
# Module Variables
#
SIMULATE=false                                    # 
DBG=true                                          # Output debug logging
SLEEP_TIME=8                                      # Time 
IPTABLES=/usr/sbin/iptables                       # Where the iptables exec is located
IPT_CMD_FILE=./iptables.cmd                       # Black list file to process
#
DEBUG() {
    if [ ${DBG} == true ]; then
	TIMESTR=`date "+%T.%3N"`
	echo "${TIMESTR} $1"
    fi
}

resetIpTables() {
	echo  "Flushing Old Rules"
	CLEARED=true
	${IPTABLES} --flush
	${IPTABLES} --delete-chain
	${IPTABLES} -P INPUT ACCEPT
	${IPTABLES} -P FORWARD ACCEPT
	${IPTABLES} -P OUTPUT ACCEPT
	${IPTABLES} -I OUTPUT -m set ! --match-set DO_NOT_LOG dst -p tcp -m state --state NEW -j LOG --log-prefix "New OUT connection: "
#	${IPTABLES} -I OUTPUT -m state --state NEW -j LOG --log-prefix "New OUT connection: "
	${IPTABLES} -N ABUSE
	${IPTABLES} -A ABUSE -j LOG --log-level 6 --log-prefix "Abuse Filter Drop: "
	${IPTABLES} -A ABUSE -j DROP
}






ipTableChanges() {
    if [[ -f "${IPT_CMD_FILE}" ]] && [[ -s "${IPT_CMD_FILE}" ]]; then

	DEBUG "[ipTableChanges] processing IPT_CMD_FILE file"
	TIMESTR=`date "+%T.%3N"`
	CHANGES=0

	while read CMD;
        do
	  IFS='#' read -ra ARR <<< "$CMD"

	  if [[ "${ARR[0]}" == "ADD" ]]; then
	    ((CHANGES++))
	    if [ ${SIMULATE} == true ] ; then
	       echo "ADD ip-address ${ARR[1]}"
	    else
	       ${IPTABLES} -A INPUT -s "${ARR[1]}" -j ABUSE
	       echo "${TIMSTR} ADD Block IpAddr: ${ARR[1]}"
	    fi
	  fi

	  if [[ "${ARR[0]}" == "REMOVE" ]]; then
    	    ((CHANGES++))
   	    if [ ${SIMULATE} == true ] ; then
	      echo "REMOVE ip-address ${ARR[1]}"
	    else
	      ${IPTABLES} -D INPUT -s "${ARR[1]}" -j ABUSE
	      echo "${TIMSTR} REMOVE Block IpAddr: ${ARR[1]}"			
	    fi
	  fi    

	done < "${IPT_CMD_FILE}"
        DEBUG "Scan complete - IP Table changes: ${CHANGES}"
	return 0;
     else
	DEBUG "[ipTableChanges] BLACKLIST file does not exists or size is zero"
	return 1
   fi
}



#=======================
# Script entry point
#=======================

# ALways start with reseting the Iptables
resetIpTables

if [ -f "${IPT_CMD_FILE}" ]; then
  rm -v "${IPT_CMD_FILE}"
fi

# Initial scan with a reset of the BAD IP addresses
./run.sh true



while :
do
    if [ ${DBG} == true ]; then
       echo "           "
    fi

    if ipTableChanges ; then
       LOOPTIME=`date "+%T.%3N"`
       DEBUG "[main] ipTableChanges called at {$LOOPTIME}"
    fi

    sleep $SLEEP_TIME

    #run job that scans logfiles and and created a new iptable.cmd (i.e IPT_CMD_FILE)
    ./run.sh false
done
