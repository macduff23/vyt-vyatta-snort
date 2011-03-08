#!/bin/sh -e
#
# Init.d script for Snort in Debian
#
# Copyright (c) 2001 Christian Hammers 
# Copyright (c) 2001-2002 Robert van der Meulen
# Copyright (c) 2002-2004 Sander Smeenk <ssmeenk@debian.org>
# Copyright (c) 2004-2007 Javier Fernandez-Sanguino <jfs@debian.org>
#
# This is free software; you may redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2,
# or (at your option) any later version.
#
# This is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License with
# the Debian operating system, in /usr/share/common-licenses/GPL;  if
# not, write to the Free Software Foundation, Inc., 59 Temple Place,
# Suite 330, Boston, MA 02111-1307 USA
#
### BEGIN INIT INFO
# Provides:          snort
# Required-Start:    $time $network $local_fs
# Required-Stop:     
# Should-Start:      $syslog
# Should-Stop:       
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Lightweight network intrusion detection system
# Description:       Intrusion detection system that will
#                    capture traffic from the network cards and will
#                    match against a set of known attacks.
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

test $DEBIAN_SCRIPT_DEBUG && set -v -x

DAEMON=/usr/sbin/snort
NAME=snort
DESC="Network Intrusion Detection System"

. /lib/lsb/init-functions

DEFAULT=/etc/default/snort
CONFIG=/etc/snort/snort.debian.conf

test -x $DAEMON || exit 1

test -r $DEFAULT || exit 1
. $DEFAULT
COMMON="$PARAMS -l $LOGDIR"

test -r $CONFIG || exit 1
. $CONFIG

INLINE_PIDFILE=/var/run/snort_.pid
INLINE_INITFILE=/var/run/snort_vyatta_init.pid

# to find the lib files
cd /etc/snort

running()
{
        PIDFILE=$1
# No pidfile, probably no daemon present
        [ ! -f "$PIDFILE" ] && return 1
        pid=`cat $PIDFILE`
# No pid, probably no daemon present
        [ -z "$pid" ] && return 1
        [ ! -d /proc/$pid ] &&  return 1
        cmd=`cat /proc/$pid/cmdline | tr "\000" "\n"|head -n 1 |cut -d : -f 1`
# No daemon
        [ "$cmd" != "$DAEMON" ] &&  return 1
        return 0
}


check_log_dir() {
# Does the logging directory belong to Snort?
	# If we cannot determine the logdir return without error
	# (we will not check it)
	# This will only be used by people using /etc/default/snort
	[ -n "$LOGDIR" ] || return 0
	[ -n "$SNORTUSER" ] || return 0
	if [ ! -e "$LOGDIR" ] ; then
		log_failure_msg "ERR: logging directory $LOGDIR does not exist"
		return 1
	elif [ ! -d "$LOGDIR" ] ; then
		log_failure_msg "ERR: logging directory $LOGDIR does not exist"
		return 1
	else
		real_log_user=`stat -c %U $LOGDIR`
	# An alternative way is to check if the snort user can create 
	# a file there...
		if [ "$real_log_user" != "$SNORTUSER" ] ; then
			log_failure_msg "ERR: logging directory $LOGDIR does not belong to the snort user $SNORTUSER"
			return 1
		fi
	fi
	return 0
}

check_root()  {
    if [ "$(id -u)" != "0" ]; then
        log_failure_msg "You must be root to start, stop or restart $NAME."
        exit 4
    fi
}

case "$1" in
  start)
        check_root
	log_daemon_msg "Starting $DESC " "$NAME"

        if ! check_log_dir; then
	    log_failure_msg " will not start $DESC!"
	    exit 5
	fi

        PIDFILE=$INLINE_PIDFILE
        CONFIGFILE=/etc/snort/snort.conf
        fail="failed (check /var/log/syslog and /var/log/snort)"
        ret=0

        if [ -e "$PIDFILE" ] && running $PIDFILE; then
	    # Do not start this instance, it is already runing
	    log_progress_msg "...already running"
	else
	    set +e
	    /sbin/start-stop-daemon --start --quiet  \
		--pidfile "$PIDFILE" \
		--exec $DAEMON -- $COMMON $DEBIAN_SNORT_OPTIONS \
		-c $CONFIGFILE >/dev/null
	    ret=$?
	    case "$ret" in
		0)
			log_progress_msg  "...done"
			;;
		*)
			log_progress_msg "...ERROR: $fail"
			;;
	    esac
	    set -e
	fi

        if  [ $ret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $ret
	;;
  stop)
        check_root
        log_daemon_msg "Stopping $DESC " "$NAME"
    
        PIDFILE=$INLINE_PIDFILE
	if [ ! -f $PIDFILE ]; then
	    log_warning_msg "No running snort instance found"
	    # LSB demands we don't exit with error here
	    exit 0
	fi

	ret=0
	set +e
	if [ -r "$PIDFILE" ]; then
	    # Change ownership of the pidfile
	    /sbin/start-stop-daemon --stop --retry 5 --quiet --oknodo \
		--pidfile "$PIDFILE" --exec $DAEMON >/dev/null
	    ret=$?
	    rm -f "$PIDFILE"
	    rm -f "$PIDFILE.lck"
	    rm -f "$INLINE_INITFILE"
	    rm -f "$INLINE_INITFILE.lck"
	else
	    log_progress_msg "cannot read $PIDFILE"
	    ret=4
	fi
	case "$ret" in
	    0)
		log_progress_msg  "...done"
		;;
	    *)
		log_progress_msg "...ERROR"
		;;
	esac
	set -e

	if  [ $ret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $ret
	;;
  restart|force-restart|reload|force-reload)
        check_root
        PIDFILE=$INLINE_PIDFILE
	if [ ! -f $PIDFILE ]; then
	    log_failure_msg "No snort instance found to be stopped!" >&2
	    exit 6
	fi

	$0 stop || true
	$0 start || true
	;;
  status)
# Non-root users can use this (if allowed to)
        log_daemon_msg "Status of snort daemon"
        err=0
        pid=0
        pidfile=$INLINE_PIDFILE
	if [ -f  "$pidfile" ] ; then
	    if [ -r "$pidfile" ] ; then
		pidval=`cat $pidfile`
		pid=1
		if ps -p $pidval | grep -q snort; then
		    log_progress_msg " OK"
		else
		    log_progress_msg " ERROR"
		    err=1
		fi
	    else
		log_progress_msg " ERROR: cannot read status file"
		err=1
	    fi
	else
	    log_progress_msg " ERROR"
	    err=1
	fi
        
	if [ $err -ne 0 ] ; then
            if [ $pid -ne 0 ] ; then
# More than one case where pidfile exists but no snort daemon
# LSB demands a '1' exit value here
                log_end_msg  1
                exit 1
            else
# No pidfiles at all
# LSB demands a '3' exit value here
                log_end_msg  3
                exit 3
            fi
        fi
        log_end_msg  0
        ;;
  config-check)
        log_daemon_msg "Checking $DESC configuration" 

	CONFIGFILE=/etc/snort/snort.conf
	COMMON=`echo $COMMON | sed -e 's/-D//' -e 's/--daq nfq//'`
	set +e
	ret=0
	fail="INVALID"
	if [ -r "$CONFIGFILE" ]; then
	    $DAEMON -T $COMMON $DEBIAN_SNORT_OPTIONS          \
		  -c $CONFIGFILE --pid-path /tmp >/dev/null 2>&1
	    ret=$?
	    rm -f /tmp/snort_{,vyatta_init}.pid{,.lck}
	else
	    fail="cannot read $CONFIGFILE"
	    ret=4
	fi
	set -e
	case "$ret" in
	    0)
		log_progress_msg "OK"
		;;
	    *)
		log_progress_msg "$fail"
		;;
	esac

        if  [ $ret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $ret
	;;
  *)
	echo "Usage: $0 {start|stop|restart|force-restart|reload|force-reload|status|config-check}"
	exit 1
	;;
esac
exit 0
