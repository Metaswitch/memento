#! /bin/sh

# @file memento.init.d
#
# Project Clearwater - IMS in the Cloud
# Copyright (C) 2014  Metaswitch Networks Ltd
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version, along with the "Special Exception" for use of
# the program along with SSL, set forth below. This program is distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details. You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
# The author can be reached by email at clearwater@metaswitch.com or by
# post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
#
# Special Exception
# Metaswitch Networks Ltd  grants you permission to copy, modify,
# propagate, and distribute a work formed by combining OpenSSL with The
# Software, or a work derivative of such a combination, even if such
# copying, modification, propagation, or distribution would otherwise
# violate the terms of the GPL. You must comply with the GPL in all
# respects for all of the code used other than OpenSSL.
# "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
# Project and licensed under the OpenSSL Licenses, or a work based on such
# software and licensed under the OpenSSL Licenses.
# "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
# under which the OpenSSL Project distributes the OpenSSL toolkit software,
# as those licenses appear in the file LICENSE-OPENSSL.

### BEGIN INIT INFO
# Provides:          memento
# Required-Start:    $remote_fs $syslog clearwater-infrastructure
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Clearwater Memento
# Description:       Clearwater Memento-HTTP
### END INIT INFO

# Author: Mike Evans <mike.evans@metaswitch.com>
#
# Please remove the "Author" lines above and replace them
# with your own name if you copy and modify this script.

# Do NOT "set -e"

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="Call List Application Server"
NAME=memento
EXECNAME=memento
PIDFILE=/var/run/$NAME/$NAME.pid
DAEMON=/usr/share/clearwater/bin/memento
HOME=/etc/clearwater
log_directory=/var/log/$NAME

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Read configuration variable file if it is present
#[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

#
# Function to pull in settings prior to starting the daemon
#
get_settings()
{
  # Set up defaults and then pull in the settings for this node.
  sas_server=0.0.0.0
  local num_cpus=$(grep processor /proc/cpuinfo | wc -l)
  num_http_threads=$num_cpus
  num_http_worker_threads=$(( $num_cpus * 50 ))
  . /etc/clearwater/config

  homestead_http_name=$(/usr/share/clearwater/bin/bracket-ipv6-address $hs_hostname)

  # Set up a default cluster_settings file if it does not exist.
  [ -f /etc/clearwater/cluster_settings ] || echo "servers=$local_ip:11211" > /etc/clearwater/cluster_settings

  # Set up defaults for user settings then pull in any overrides.
  log_level=2
  [ -r /etc/clearwater/user_settings ] && . /etc/clearwater/user_settings

  # Work out which features are enabled.
  if [ -d /etc/clearwater/features.d ]
  then
    for file in $(find /etc/clearwater/features.d -type f)
    do
      [ -r $file ] && . $file
    done
  fi

  [ -z "$target_latency_us" ] || target_latency_us_arg="--target-latency-us $target_latency_us"
  [ -z "$max_tokens" ] || max_tokens_arg="--max-tokens $max_tokens"
  [ -z "$init_token_rate" ] || init_token_rate_arg="--init-token-rate $init_token_rate"
  [ -z "$min_token_rate" ] || min_token_rate_arg="--min-token-rate $min_token_rate"
  [ -z "$signaling_namespace" ] || namespace_prefix="ip netns exec $signaling_namespace"
  [ -z "$exception_max_ttl" ] || exception_max_ttl_arg="--exception-max-ttl $exception_max_ttl"
  [ -z "$memento_api_key" ] || api_key_arg="--api-key $memento_api_key"
  [ -z "$cassandra_hostname" ] || cassandra_arg="--cassandra=$cassandra_hostname"
  [ -z "$memento_auth_store" ] || astaire_arg="--astaire=$memento_auth_store"
}

#
# Function that starts the daemon/service
#
do_start()
{
        # Return
        #   0 if daemon has been started
        #   1 if daemon was already running
        #   2 if daemon could not be started

        # Allow us to write to the pidfile directory
        install -m 755 -o $NAME -g root -d /var/run/$NAME && chown -R $NAME /var/run/$NAME

        start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --test > /dev/null \
                || return 1

        # daemon is not running, so attempt to start it.
        export LD_LIBRARY_PATH=/usr/share/clearwater/lib
        ulimit -Hn 1000000
        ulimit -Sn 1000000
        ulimit -c unlimited
        # enable gdb to dump a parent memento process's stack
        echo 0 > /proc/sys/kernel/yama/ptrace_scope
        get_settings
        DAEMON_ARGS="--localhost $local_ip
                     --http $local_ip
                     --http-threads $num_http_threads
                     --http-worker-threads $num_http_worker_threads
                     --homestead-http-name $homestead_http_name
                     --home-domain $home_domain
                     --access-log $log_directory
                     $cassandra_arg
                     $astaire_arg
                     $target_latency_us_arg
                     $max_tokens_arg
                     $init_token_rate_arg
                     $min_token_rate_arg
                     $exception_max_ttl_arg
                     --log-file $log_directory
                     --log-level $log_level
                     --sas $sas_server,$NAME@$public_hostname
                     $api_key_arg"
        [ "$http_blacklist_duration" = "" ]       || DAEMON_ARGS="$DAEMON_ARGS --http-blacklist-duration=$http_blacklist_duration"
        [ "$astaire_blacklist_duration" = "" ]    || DAEMON_ARGS="$DAEMON_ARGS --astaire-blacklist-duration=$astaire_blacklist_duration"

        $namespace_prefix start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --chuid $NAME --chdir $HOME -- $DAEMON_ARGS --daemon --pidfile=$PIDFILE \
                || return 2
        # Add code here, if necessary, that waits for the process to be ready
        # to handle requests from services started subsequently which depend
        # on this one.  As a last resort, sleep for some time.
}

#
# Function that stops the daemon/service
#
do_stop()
{
        # Return
        #   0 if daemon has been stopped
        #   1 if daemon was already stopped
        #   2 if daemon could not be stopped
        #   other if a failure occurred
        start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $EXECNAME
        RETVAL="$?"
        return "$RETVAL"
}

#
# Function that aborts the daemon/service
#
# This is very similar to do_stop except it sends SIGABRT to dump a core file
# and waits longer for it to complete.
#
do_abort()
{
        # Return
        #   0 if daemon has been stopped
        #   1 if daemon was already stopped
        #   2 if daemon could not be stopped
        #   other if a failure occurred
        start-stop-daemon --stop --quiet --retry=ABRT/60/KILL/5 --pidfile $PIDFILE --name $EXECNAME
        RETVAL="$?"
        return "$RETVAL"
}

#
# Function that sends a SIGHUP to the daemon/service
#
do_reload() {
        #
        # If the daemon can reload its configuration without
        # restarting (for example, when it is sent a SIGHUP),
        # then implement that here.
        #
        start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE --name $EXECNAME
        return 0
}

# There should only be at most one memento process, and it should be the one in /var/run/memento.pid.
# Sanity check this, and kill and log any leaked ones.
if [ -f $PIDFILE ] ; then
  leaked_pids=$(pgrep -f "^$DAEMON" | grep -v $(cat $PIDFILE))
else
  leaked_pids=$(pgrep -f "^$DAEMON")
fi
if [ -n "$leaked_pids" ] ; then
  for pid in $leaked_pids ; do
    logger -p daemon.error -t $NAME Found leaked memento $pid \(correct is $(cat $PIDFILE)\) - killing $pid
    kill -9 $pid
  done
fi

case "$1" in
  start)
        [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
        do_start
        case "$?" in
                0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
                2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
  stop)
        [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
        do_stop
        case "$?" in
                0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
                2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
  status)
        status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
        ;;
  reload|force-reload)
        #
        # If do_reload() is not implemented then leave this commented out
        # and leave 'force-reload' as an alias for 'restart'.
        #
        do_reload
        ;;
  restart)
        #
        # If the "reload" option is implemented then remove the
        # 'force-reload' alias
        #
        log_daemon_msg "Restarting $DESC" "$NAME"
        do_stop
        case "$?" in
          0|1)
                do_start
                case "$?" in
                        0) log_end_msg 0 ;;
                        1) log_end_msg 1 ;; # Old process is still running
                        *) log_end_msg 1 ;; # Failed to start
                esac
                ;;
          *)
                # Failed to stop
                log_end_msg 1
                ;;
        esac
        ;;
  abort)
        log_daemon_msg "Aborting $DESC" "$NAME"
        do_abort
        ;;
  abort-restart)
        log_daemon_msg "Abort-Restarting $DESC" "$NAME"
        do_abort
        case "$?" in
          0|1)
                do_start
                case "$?" in
                        0) log_end_msg 0 ;;
                        1) log_end_msg 1 ;; # Old process is still running
                        *) log_end_msg 1 ;; # Failed to start
                esac
                ;;
          *)
                # Failed to stop
                log_end_msg 1
                ;;
        esac
        ;;
  *)
        echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload|restart|abort|abort-restart}" >&2
        exit 3
        ;;
esac

:
