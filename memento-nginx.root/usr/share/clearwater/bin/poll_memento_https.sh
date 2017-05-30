#!/bin/bash

# @file poll_memento_https.sh
#
# Copyright (C) Metaswitch Networks 2014
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

# This script checks that port 11888 is open to poll memento and check whether it
# is healthy.

# In case memento has only just restarted, give it a few seconds to come up
sleep 5

# Read the config, defaulting appropriately.
. /etc/clearwater/config

if [ -z $memento_hostname ]
then
  memento_hostname="memento.$home_domain"
fi

# Send HTTP request and check that the response is "OK".
curl -f -g -m 2 -s --insecure -H 'Host: $memento_hostname' https://127.0.0.1/ping 2> /tmp/poll-memento-https.sh.stderr.$$ | tee /tmp/poll-memento-https.sh.stdout.$$ | head -1 | egrep -q "^OK$"
rc=$?

# Check the return code and log if appropriate.
if [ $rc != 0 ] ; then
  echo HTTPS failed to https://127.0.0.1/ping >&2
  cat /tmp/poll-memento-https.sh.stderr.$$ >&2
  cat /tmp/poll-memento-https.sh.stdout.$$ >&2
fi
rm -f /tmp/poll-memento-https.sh.stderr.$$ /tmp/poll-memento-https.sh.stdout.$$

exit $rc
