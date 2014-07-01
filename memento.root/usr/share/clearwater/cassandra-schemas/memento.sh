#! /bin/bash
if [[ ! -e /var/lib/cassandra/data/memento ]];
then
    echo "CREATE KEYSPACE memento WITH strategy_class = 'SimpleStrategy' AND strategy_options:replication_factor = 2;" | cqlsh -2
fi
