#! /bin/bash
. /usr/share/clearwater/cassandra_schema_utils.sh

cassandra_hostname="127.0.0.1"

. /etc/clearwater/config

quit_if_no_cassandra

CQLSH="/usr/share/clearwater/bin/run-in-signaling-namespace cqlsh $cassandra_hostname"

if [[ ! -e /var/lib/cassandra/data/memento ]] || \
   [[ $cassandra_hostname != "127.0.0.1" ]];
then
  count=0
  /usr/share/clearwater/bin/poll_cassandra.sh --no-grace-period

  while [ $? -ne 0 ]; do
    ((count++))
    if [ $count -gt 120 ]; then
      echo "Cassandra isn't responsive, unable to add schemas"
      exit 1
    fi

    sleep 1
    /usr/share/clearwater/bin/poll_cassandra.sh --no-grace-period
  done

  # replication_str is set up by
  # /usr/share/clearwater/cassandra-schemas/replication_string.sh
  echo "CREATE KEYSPACE memento WITH REPLICATION = $replication_str;
        USE memento;
        CREATE TABLE call_lists (impu text PRIMARY KEY, dummy text) WITH COMPACT STORAGE and read_repair_chance = 1.0;
  " | $CQLSH
fi
