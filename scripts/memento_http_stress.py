#!/usr/bin/env python

import time, itertools, argparse, subprocess

# How frequently to output statistics.
STATS_INTERVAL = 60.0

def parse_args():
    '''
    Parse the program's arguments.
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument("start_dn", type=int, help="Start of the DN range")
    parser.add_argument("end_dn", type=int, help="End of the DN range")
    parser.add_argument("host", help="Memento hostname")
    parser.add_argument("domain", help="The subscribers' home domain")
    parser.add_argument("target_rate", nargs="?", type=float, help="Target request rate (requests / s)")
    return parser.parse_args()

def get_call_list(dn, host, domain):
    '''
    Retrieve a DN's call list entry.
    '''
    rc = subprocess.call(['curl',
                          'https://%(host)s/org.projectclearwater.call-list/users/sip%%3A%(dn)d%%40%(domain)s/call-list.xml' % {'dn': dn, 'host': host, 'domain': domain},
                          # Use digest auth.
                          '--digest',
                          '--user', '%(dn)d@%(domain)s:7kkzTyGW' % {'dn': dn, 'domain': domain},
                          # Don't check SSL certificates
                          '--insecure',
                          # Request gzip compression (among other schemes).
                          '--compressed',
                          # Causes curl to fail with an error code if the
                          # connection or HTTP request fails.
                          '-f',
                          # Silent mode.
                          '-s',
                          # Even with silent mode, curl still prints the
                          # response body by default.
                          '-o', '/dev/null',
                         ])
    if rc != 0:
        print "%d: curl failed with rc=%d" % (dn, rc)

def main():
    '''
    Loop retrieving the call lists of different DNs.
    '''
    args = parse_args()

    start_time = time.time()
    last_tick = start_time

    count_since_last_stats = 0
    time_of_last_stats = start_time

    # Process each DN in sequence, and go back to the start when we get to the
    # end.
    for dn in itertools.cycle(xrange(args.start_dn, args.end_dn + 1)):
        get_call_list(dn, args.host, args.domain)

        count_since_last_stats += 1
        curr_time = time.time()

        if curr_time - time_of_last_stats > STATS_INTERVAL:
            # Time to output some stats.  Calculate the current request rate.
            rate = (count_since_last_stats / (curr_time - time_of_last_stats))
            print "%s: rate = %f" % (time.asctime(), rate)

            # Reset stats.
            count_since_last_stats = 0
            time_of_last_stats = curr_time

        # If we're trying to hit a certain request rate, work out how long we
        # need to sleep to achieve it.  Oftherwise, just go as fast as we can.
        if args.target_rate:
            next_tick = last_tick + 1.0 / args.target_rate
            sleep_time = next_tick - curr_time
            if sleep_time > 0:
                time.sleep(sleep_time)
            last_tick = next_tick

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
