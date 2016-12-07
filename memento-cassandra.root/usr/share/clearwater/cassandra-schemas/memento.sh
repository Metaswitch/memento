#! /bin/bash
. /usr/share/clearwater/cassandra_schema_utils.sh

quit_if_no_cassandra

if [[ ! -e /var/lib/cassandra/data/memento ]];
then
  echo "Adding Cassandra schemas..."
  count=0
  /usr/share/clearwater/bin/poll_cassandra.sh --no-grace-period > /dev/null 2>&1

  while [ $? -ne 0 ]; do
    ((count++))
    if [ $count -gt 120 ]; then
      echo "Cassandra isn't responsive, unable to add schemas"
      exit 1
    fi

    sleep 1
    /usr/share/clearwater/bin/poll_cassandra.sh --no-grace-period > /dev/null 2>&1
  done

  # replication_str is set up by
  # /usr/share/clearwater/cassandra-schemas/replication_string.sh
  echo "CREATE KEYSPACE IF NOT EXISTS memento WITH REPLICATION = $replication_str;
        USE memento;
        CREATE TABLE IF NOT EXISTS call_lists (impu text PRIMARY KEY, dummy text) WITH COMPACT STORAGE and read_repair_chance = 1.0;
  " | cqlsh
fi
