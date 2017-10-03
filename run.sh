#!/bin/bash
LOCKFILE=collector.lock
LOGFILE=collector.log

if [ -f $LOCKFILE ]; then
    # Check if the collector is running
    MYPID=`head -n 1 "${LOCKFILE}"`
    TEST_RUNNING=`ps -p ${MYPID} | grep ${MYPID}`
    if [ -z "${TEST_RUNNING}" ]; then
        echo "`date` Collector not running, but lockfile exists. Removing the lockfile." >> $LOGFILE
        rm $LOCKFILE
    else
        echo "`date` Collector is still running. Aborting." >> $LOGFILE
        exit 1
    fi
fi
echo $$ > "${LOCKFILE}"

.env/bin/python collector.py

rm $LOCKFILE
exit 0