#! /bin/bash
if [[ ! -e /var/lib/cassandra/data/memento ]];
then
    echo "CREATE KEYSPACE memento WITH WITH REPLICATION = {'class': 'SimpleStrategy', 'replication_factor': 2};
          USE memento;
          CREATE TABLE call_lists (impu text PRIMARY KEY, dummy text) WITH read_repair_chance = 1.0;
    " | cqlsh
fi
