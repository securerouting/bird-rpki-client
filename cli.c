/*
 * This file is part of BIRD-RPKI-Client.
 *
 * This software was originally based off the BIRD-RTRLib-CLI by
 * written by Mehmet Ceyran, in cooperation with: CST group, Freie
 * Universitaet Berlin Website:
 * https://github.com/rtrlib/BIRD-RTRLib-CLI
 *
 * It has been heavily modified by Parsons, Inc. The modifications and
 * additions are licensed, as the original, under the LGPLv3.  You
 * should have received a copy of the GNU Lesser General Public
 * License along with BIRD-RTRLib-CLI; see the file COPYING.
 *
 * BIRD-RPKI-Client modified by Michael Baer, Parsons, Inc (c)
 * 2014-2016
 *
 *
 * Excerpts from the original BIRD-RTRLib-CLI license statement
 * follows:
 * BIRD-RTRLib-CLI is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 */


#include <argp.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"

#define ARGKEY_DEBUG          'd'
#define ARGKEY_NO_SYSLOG      'S'

#define ARGKEY_NO_BIRD        'B'
#define ARGKEY_BIRD_SOCKET    'b'
#define ARGKEY_BIRD_ROA_TABLE 't'

#define ARGKEY_RTR_ADDRESS    'r'

#define ARGKEY_RTRSSH_ENABLE  's'
#define ARGKEY_RTRSSH_HOSTKEY 0x100
#define ARGKEY_RTRSSH_USERNAME 0x101
#define ARGKEY_RTRSSH_PRIVKEY 0x102
#define ARGKEY_RTRSSH_PUBKEY 0x103

#define ARGKEY_RTR_REFRESH   'R'
#define ARGKEY_RTR_EXPIRE    'E'
#define ARGKEY_RTR_RETRY     'Y'

#define ARGKEY_SNMP_SUPPORT  'M'

#define ARGKEY_SNMP_DEBUG    'D'
#define ARGKEY_SNMP_USAGE    'U'
#define ARGKEY_SNMP_MASTER   'm'
#define ARGKEY_SNMP_SYSLOG   'L'
#define ARGKEY_SNMP_ASOCK    'x'


// Parser function for argp_parse().
static error_t argp_parser(int key, char *arg, struct argp_state *state) {
  // Shortcut to config object passed to argp_parse().
  struct config *config = state->input;
  
  // Process command line argument.
  switch (key) {
  case ARGKEY_NO_BIRD:
    config->support_bird = 0;
    break;
  case  ARGKEY_DEBUG:
    config->debug = 1;
    break;
  case ARGKEY_NO_SYSLOG:
    config->no_syslog = 1;
    break;
  case ARGKEY_BIRD_SOCKET:
    // Process BIRD socket path.
    config->bird_socket_path = arg;
    break;
  case ARGKEY_BIRD_ROA_TABLE:
    config->bird_roa_table = arg;
    break;
  case ARGKEY_RTR_ADDRESS:
    config->rtr_host = strtok(arg, ":");
    config->rtr_port = strtok(0, ":");
    break;
#ifdef RTRLIB_HAVE_LIBSSH
  case ARGKEY_RTRSSH_ENABLE:
    config->rtr_connection_type = ssh;
    break;
  case ARGKEY_RTRSSH_USERNAME:
    config->rtr_ssh_username = arg;
    break;
  case ARGKEY_RTRSSH_HOSTKEY:
    config->rtr_ssh_hostkey_file = arg;
    break;
  case ARGKEY_RTRSSH_PRIVKEY:
    config->rtr_ssh_privkey_file = arg;
    break;
  case ARGKEY_RTRSSH_PUBKEY:
    config->rtr_ssh_pubkey_file = arg;
    break;
#endif
  case ARGKEY_RTR_REFRESH:
    config->rtr_refresh = atoi(arg);
    if ( config->rtr_refresh < BIRD_RTRLIB_MIN_RTR_REFRESH_RATE ||
	 config->rtr_refresh > BIRD_RTRLIB_MAX_RTR_REFRESH_RATE ) {
      argp_error(state,
		 "Refresh rate must be: %d <= refresh <= %d",
		 BIRD_RTRLIB_MIN_RTR_REFRESH_RATE,
		 BIRD_RTRLIB_MAX_RTR_REFRESH_RATE);
    }
    config->rtr_expire = 2 * config->rtr_refresh;
    if (config->rtr_expire < BIRD_RTRLIB_MIN_RTR_EXPIRE_RATE)
      config->rtr_expire = BIRD_RTRLIB_MIN_RTR_EXPIRE_RATE;
    else if (config->rtr_expire > BIRD_RTRLIB_MAX_RTR_EXPIRE_RATE)
      config->rtr_expire = BIRD_RTRLIB_MAX_RTR_EXPIRE_RATE;
    break;
  case ARGKEY_RTR_EXPIRE:
    config->rtr_expire = atoi(arg);
    if ( config->rtr_expire < BIRD_RTRLIB_MIN_RTR_EXPIRE_RATE ||
	 config->rtr_expire > BIRD_RTRLIB_MAX_RTR_EXPIRE_RATE ) {
      argp_error(state,
		 "Expire rate must be: %d <= expire <= %d",
		 BIRD_RTRLIB_MIN_RTR_EXPIRE_RATE,
		 BIRD_RTRLIB_MAX_RTR_EXPIRE_RATE);
    }
    break;
  case ARGKEY_RTR_RETRY:
    config->rtr_retry = atoi(arg);
    if ( config->rtr_retry < BIRD_RTRLIB_MIN_RTR_RETRY_RATE ||
	 config->rtr_retry > BIRD_RTRLIB_MAX_RTR_RETRY_RATE ) {
      argp_error(state,
		 "Retry rate must be: %d <= retry <= %d",
		 BIRD_RTRLIB_MIN_RTR_RETRY_RATE,
		 BIRD_RTRLIB_MAX_RTR_RETRY_RATE);
    }
    break;

// SNMP config
  case ARGKEY_SNMP_SUPPORT:
    config->support_mib = 1;
    break;
  case ARGKEY_SNMP_DEBUG:
    config->support_mib = 1;
    config->snmp_config.D_debug      = 1;
    config->snmp_config.debug_tokens = arg;
    break;
  case ARGKEY_SNMP_USAGE:
    config->support_mib = 1;
    config->snmp_config.H_config_usage = 1;
    break;
  case ARGKEY_SNMP_MASTER:
    config->support_mib = 1;
    config->snmp_config.M_master       = 1;
    config->snmp_config.master_address = arg;
    break;
  case ARGKEY_SNMP_SYSLOG:
    config->support_mib = 1;
    config->snmp_config.L_no_syslog = 1;
    break;
  case ARGKEY_SNMP_ASOCK:
    config->support_mib = 1;
    config->snmp_config.x_agentx_socket = 1;
    config->snmp_config.agentx_socket   = arg;
    break;

  default:
    // Process unknown argument.
    return ARGP_ERR_UNKNOWN;
  }

  // Return success.
  return 0;
}

// Parses the specified command line arguments into the program config.
int parse_cli(int argc, char **argv, struct config *config) {
    // Command line options definition.
    const struct argp_option argp_options[] = {
      { "DEBUG",
	ARGKEY_DEBUG,
	0,
	0,
	"Turn on debug output extra output to standard error."
	" ",
	0
      },
      { "NO_SYSLOG",
	ARGKEY_NO_SYSLOG,
	0,
	0,
	"Do not log to syslog."
	" ",
	0
      },
      { "NO_BIRD",
	ARGKEY_NO_BIRD,
	0,
	0,
	"Do not connect to a BIRD router."
	" ",
	0
      },
      {  "bird-socket",
	 ARGKEY_BIRD_SOCKET,
	 "<BIRD_SOCKET_PATH>",
	 0,
	 "Path to the BIRD control socket.",
	 0
      },
      {	"bird-roa-table",
	ARGKEY_BIRD_ROA_TABLE,
	"<BIRD_ROA_TABLE>",
	0,
	"(optional) Name of the BIRD ROA table for RPKI ROA imports.",
	0
      },
      {	"rtr-address",
	ARGKEY_RTR_ADDRESS,
	"<RTR_HOST>:<RTR_PORT>",
	0,
	"Address of the RPKI-RTR server.",
	1
      },
      {	"ssh",
	ARGKEY_RTRSSH_ENABLE,
	0,
	0,
	"Use an SSH connection instead of plain TCP."
	" ",
	1
      },
      {	"rtr-refresh",
	ARGKEY_RTR_REFRESH,
	"<RTR_REFRESH>",
	0,
	"(optional) Integer interval in seconds.\n"
	"Time between serial queries that are sent to the RTR-RTR server. "
	BIRD_RTRLIB_RTR_REFRESH_RATE_RANGE_TEXT
	". The Default is 1800 seconds.\n",
	1
      },
      {	"rtr-expire",
	ARGKEY_RTR_EXPIRE,
	"<RTR_EXPIRED>",
	0,
	"(optional) Integer interval in seconds.\n"
	"Received prefix records are deleted if the client is unable to "
	"refresh data for this time period. "
	BIRD_RTRLIB_RTR_EXPIRE_RATE_RANGE_TEXT
	". The default expire_interval is twice the rtr-refresh interval.",
	1
      },
      {	"rtr-retry",
	ARGKEY_RTR_RETRY,
	"<RTR_RETRY>",
	0,
	"(optional) Integer interval in seconds.\n"
	"Time between retrying a failed Serial or Reset Query. "
	BIRD_RTRLIB_RTR_RETRY_RATE_RANGE_TEXT
	". The default is 600.",
	1
      },
      {	"rtr-ssh-hostkey",
	ARGKEY_RTRSSH_HOSTKEY,
	"<RTR_SSH_HOSTKEY_FILE>",
	0,
	"(optional) Path to a file containing the SSH host key of the RTR "
	"server. Uses the default known_hosts file if not specified.",
	2
      },
      {	"rtr-ssh-username",
	ARGKEY_RTRSSH_USERNAME,
	"<RTR_SSH_USERNAME>",
	0,
	"Name of the user to be authenticated with the RPKI-RTR server. "
	"Mandatory for SSH connections.\n",
	2
      },
      {	"rtr-ssh-privkey",
	ARGKEY_RTRSSH_PRIVKEY,
	"<RTR_SSH_PRIVKEY_FILE>",
	0,
	"(optional) Path to a file containing the private key of the user "
	"to be authenticated with the RTR server if an SSH connection is "
	"used. Uses the user's default identity file if not specified.",
	2
      },
      { "rtr-ssh-pubkey",
	ARGKEY_RTRSSH_PUBKEY,
	"<RTR_SSH_PUBKEY_FILE>",
	0,
	"(optional) Path to a file containing the public key of the user "
	"to be authenticated with the RTR server if an SSH connection is "
	"used. Uses the user's default public key file if not specified.",
	2
      },
      { "rtr-ssh-pubkey",
	ARGKEY_RTRSSH_PUBKEY,
	"<RTR_SSH_PUBKEY_FILE>",
	0,
	"(optional) Path to a file containing the public key of the user "
	"to be authenticated with the RTR server if an SSH connection is "
	"used. Uses the user's default public key file if not specified.",
	2
      },
// SNMP config
      { "SNMP_SUPPORT",
	ARGKEY_SNMP_SUPPORT,
	0,
	0,
	"Start SNMP agent to support RPKI-RTR-MIB."
	" ",
	3
      },
      { "SNMP_DEBUG",
	ARGKEY_SNMP_DEBUG,
	"<SNMP_DEBUG_TOKEN>",
	0,
	"TOKEN[,TOKEN,...]\n"
	"Turn on SNMP debugging output for the given TOKEN(s). "
	"Without any tokens specified, it defaults to printing "
	"all the tokens (which is equivalent to the keyword 'ALL'). "
	"You might want to try ALL for extremely verbose output.",
	4
      },
      { "SNMP_USAGE",
	ARGKEY_SNMP_USAGE,
	0,
	0,
	"Display a list of Net-SNMP configuration file directives "
	"understood by the Net-SNMP agent and then exit.",
	4
      },
      { "SNMP_MASTER",
	ARGKEY_SNMP_MASTER,
	"<SNMP_MASTER>",
	0,
	"ADDRESS[:PORT]\n"
	"Run as a normal SNMP Agent instead of an AgentX sub-agent.",
	4
      },
      { "SNMP_SYSLOG",
	ARGKEY_SNMP_SYSLOG,
	0,
	0,
	"Do not open a log file for SNMP messages. Print all SNMP "
	"messages to stderr.",
	4
      },
      { "SNMP_ASOCK",
	ARGKEY_SNMP_ASOCK,
	"<SNMP_ASOCK>",
	0,
	"SOCKET-PATH\n"
	"Connect to master agent at ADDRESS (default /var/agentx/master).",
	4
      },
      {0}
    };

    // argp structure to be passed to argp_parse().
    const struct argp argp = {
      argp_options,
      &argp_parser,
      NULL,
      "RTRLIB <-> BIRD interface",
      NULL,
      NULL,
      NULL
    };

    // Parse command line. Exits on errors.
    argp_parse(&argp, argc, argv, 0, NULL, config);


    // Return success.
    return 1;
}
