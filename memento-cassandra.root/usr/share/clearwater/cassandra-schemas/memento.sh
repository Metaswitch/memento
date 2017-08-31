#! /bin/bash

cassandra_hostname="127.0.0.1"

. /etc/clearwater/config
. /usr/share/clearwater/utils/check-root-permissions 1
. /usr/share/clearwater/cassandra_schema_utils.sh

quit_if_no_cassandra

echo "Adding/updating Cassandra schemas..."

# Wait for the cassandra cluster to come online
count=0
/usr/share/clearwater/bin/poll_cassandra.sh --no-grace-period > /dev/null 2>&1

while [ $? -ne 0 ]; do
  ((count++))
  if [ $count -gt 120 ]; then
    echo "Cassandra isn't responsive, unable to add/update schemas yet"
    exit 1
  fi

  sleep 1
  /usr/share/clearwater/bin/poll_cassandra.sh --no-grace-period > /dev/null 2>&1

done

CQLSH="/usr/share/clearwater/bin/run-in-signaling-namespace cqlsh"

rc=0

if [[ ! -e /var/lib/cassandra/data/memento ]] || \
   [[ $cassandra_hostname != "127.0.0.1" ]];
then
  $CQLSH -e "CREATE KEYSPACE IF NOT EXISTS memento WITH REPLICATION = $replication_str;
             USE memento;
             CREATE TABLE IF NOT EXISTS call_lists (impu text PRIMARY KEY, dummy text) WITH COMPACT STORAGE and read_repair_chance = 1.0;"
  rc=$?
fi

exit $rc
