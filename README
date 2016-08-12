
BIRD RPKI Client
==================

1 Introduction
--------------

This tool uses the RTRlib (http://rtrlib.realmv6.org/) client library to
communicate between the BIRD Internet Routing Daemon
(http://bird.network.cz) and a RPKI/Router Server.  It is intended to
serve three purposes.

The first is to maintain the ROA table within a running BIRD
daemon. It does this by automatically adding and deleting ROA
information into a table within the BIRD daemon using a control
socket.  This uses a ROA table that is integrated to the BIRD software
package and will function without modifying BIRD.

The second purpose of the BIRD RPKI Client is to download router keys
from a RPKI/Router Server and place them on the local machine for
BGPSEC use.  These keys can be used by the BGPSec supporting BIRD
software that is also available from this sites.

The third is to provide support for the RPKI-RTR-MIB
(http://datatracker.ietf.org/doc/rfc6945/) using the net-snmp toolkit
(http://www.net-snmp.org/).  This software will function as a SNMP
daemon or sub-agent to provide support for the RPKI-RTR-MIB.


2 Requirements
--------------

To build the command line interface:
  1. the CMake build system
  2. RTRlib version v0.3.6 (not compatible with earlier versions)
  3. Net-SNMP
  3. BGPsec supporting BIRD or vanilla BIRD installed.


3 Compilation
-------------

cmake .
make


4 Using
-------

4.1 ROA Tables
--------------

* Create a ROA table in the bird.conf.  For more in depth
  documentation of how to use and configure filters and the ROA table
  within BIRD, please see the BIRD website: http://bird.network.cz

  The following is a short example:

    roa table rtr_roa_table ;

    filter roa_filter {
           if roa_check(rtr_roa_table) = ROA_INVALID then { 
              print "ROA INVALID, rejecting: ", net, " ASN ", bgp_path.last; 
              reject; 
           }
           if roa_check(rtr_roa_table) = ROA_UNKNOWN then { 
              print "ROA UNKNOWN, accepting: ", net, " ASN ", bgp_path.last; 
           }
           accept;
     

  And within the bgp protocol configuration:

    protocol bgp{
             ...
             import filter roa_filter;
             ...
    }


* Example command line to start bird-rpki-client connecting to a
  BIRD control socket, a RPKI cache server and starting an SNMP agent
  to provide RPKI-RTR-MIB support on port 16161:

  ./bird-rpki-client -b /var/run/bird.ctl -r rpki-validator.realmv6.org:8282 --bird-roa-table=rtr_roa_table -M -m :16161


4.2 Router Keys
---------------

The bird-rpki-client will automatically download the available
routers into /usr/share/bird/bgpsec-keys/ using the naming convention
that the BIRD BGPSEC patched code will look for it (currently
'/usr/share/bird/bgpsec-keys/ASN.SKI.0.key').


4.3 RPKI-RTR-MIB
----------------

Use the -M flag to turn on the default MIB support for the
RPKI-RTR-MIB.  By default the MIB runs as an agentx sub-agent.  To run
as a master agent use the '-m ADDRESS' flag.  The snmp configuration
file is bird-rpki-client.conf.  You will need to understand SNMP in
general and Net-SNMP configuration specifically to use this MIB.  See
the http://www.net-snmp.org/ website for further SNMP/Net-SNMP
documentation.


5 Help
------
./bird-rpki-client --help
RTRLIB <-> BIRD interface

  -b, --bird-socket=<BIRD_SOCKET_PATH>
                             Path to the BIRD control socket.
  -B, --NO_BIRD              Do not connect to a BIRD router. 
  -d, --DEBUG                Turn on debug output extra output to standard
                             error. 
  -S, --NO_SYSLOG            Do not log to syslog. 
  -t, --bird-roa-table=<BIRD_ROA_TABLE>
                             (optional) Name of the BIRD ROA table for RPKI ROA
                             imports.
  -E, --rtr-expire=<RTR_EXPIRED>   (optional) Integer interval in seconds.
                             Received prefix records are deleted if the client
                             is unable to refresh data for this time period.
                             Acceptable range is 600 <= expire <= 172800. The
                             default expire_interval is twice the rtr-refresh
                             interval.
  -r, --rtr-address=<RTR_HOST>:<RTR_PORT>
                             Address of the RPKI-RTR server.
  -R, --rtr-refresh=<RTR_REFRESH>
                             (optional) Integer interval in seconds.
                             Time between serial queries that are sent to the
                             RTR-RTR server. Acceptable range is 1 <= refresh
                             <= 86400. The Default is 1800 seconds.

  -s, --ssh                  Use an SSH connection instead of plain TCP. 
  -Y, --rtr-retry=<RTR_RETRY>   (optional) Integer interval in seconds.
                             Time between retrying a failed Serial or Reset
                             Query. Acceptable range is 1 <= retry <= 7200. The
                             default is 600.
      --rtr-ssh-hostkey=<RTR_SSH_HOSTKEY_FILE>
                             (optional) Path to a file containing the SSH host
                             key of the RTR server. Uses the default
                             known_hosts file if not specified.
      --rtr-ssh-privkey=<RTR_SSH_PRIVKEY_FILE>
                             (optional) Path to a file containing the private
                             key of the user to be authenticated with the RTR
                             server if an SSH connection is used. Uses the
                             user's default identity file if not specified.
      --rtr-ssh-pubkey=<RTR_SSH_PUBKEY_FILE>
                             (optional) Path to a file containing the public
                             key of the user to be authenticated with the RTR
                             server if an SSH connection is used. Uses the
                             user's default public key file if not specified.
      --rtr-ssh-pubkey=<RTR_SSH_PUBKEY_FILE>
                             (optional) Path to a file containing the public
                             key of the user to be authenticated with the RTR
                             server if an SSH connection is used. Uses the
                             user's default public key file if not specified.
      --rtr-ssh-username=<RTR_SSH_USERNAME>
                             Name of the user to be authenticated with the
                             RPKI-RTR server. Mandatory for SSH connections.

  -M, --SNMP_SUPPORT         Start SNMP agent to support RPKI-RTR-MIB. 
  -D, --SNMP_DEBUG=<SNMP_DEBUG_TOKEN>
                             TOKEN[,TOKEN,...]
                             Turn on SNMP debugging output for the given
                             TOKEN(s). Without any tokens specified, it
                             defaults to printing all the tokens (which is
                             equivalent to the keyword 'ALL'). You might want
                             to try ALL for extremely verbose output.
  -L, --SNMP_SYSLOG          Do not open a log file for SNMP messages. Print
                             all SNMP messages to stderr.
  -m, --SNMP_MASTER=<SNMP_MASTER>
                             ADDRESS[:PORT]
                             Run as a normal SNMP Agent instead of an AgentX
                             sub-agent.
  -U, --SNMP_USAGE           Display a list of Net-SNMP configuration file
                             directives understood by the Net-SNMP agent and
                             then exit.
  -x, --SNMP_ASOCK=<SNMP_ASOCK>   SOCKET-PATH
                             Connect to master agent at ADDRESS (default
                             /var/agentx/master).
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.


License
-------

This file has been modified from the original BIRD-RTRlib-CLI by
Parsons, Inc. The modifications and additions are licensed, as the
original, under the LGPLv3.  See the included COPYING file.

Modified by Michael Baer, Parsons, Inc (c) 2015-2016

