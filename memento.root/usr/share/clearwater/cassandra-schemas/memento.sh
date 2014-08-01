#! /bin/bash
if [[ ! -e /var/lib/cassandra/data/memento ]];
then
    echo "CREATE KEYSPACE memento WITH strategy_class='org.apache.cassandra.locator.SimpleStrategy' AND strategy_options:replication_factor=2;
          USE memento;
          CREATE TABLE call_lists (impu text PRIMARY KEY, dummy text) WITH read_repair_chance = 1.0;
    " | cqlsh -2
fi
