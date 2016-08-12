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


#ifndef BIRD_RTRLIB_CLI__CONFIG_H
#define	BIRD_RTRLIB_CLI__CONFIG_H

#define BIRD_RTRLIB_MIN_RTR_REFRESH_RATE     1
#define BIRD_RTRLIB_MAX_RTR_REFRESH_RATE     86400
#define BIRD_RTRLIB_DEFAULT_RTR_REFRESH_RATE 1800
#define BIRD_RTRLIB_RTR_REFRESH_RATE_RANGE_TEXT "Acceptable range is 1 <= refresh <= 86400"

#define BIRD_RTRLIB_MIN_RTR_EXPIRE_RATE      600
#define BIRD_RTRLIB_MAX_RTR_EXPIRE_RATE      172800
#define BIRD_RTRLIB_DEFAULT_RTR_EXPIRE_RATE  3600
#define BIRD_RTRLIB_RTR_EXPIRE_RATE_RANGE_TEXT  "Acceptable range is 600 <= expire <= 172800"

#define BIRD_RTRLIB_MIN_RTR_RETRY_RATE       1
#define BIRD_RTRLIB_MAX_RTR_RETRY_RATE       7200
#define BIRD_RTRLIB_DEFAULT_RTR_RETRY_RATE   600
#define BIRD_RTRLIB_RTR_RETRY_RATE_RANGE_TEXT  "Acceptable range is 1 <= retry <= 7200"

#include "rpkiRtr_subagent.h"

/// Specifies a type of server connection to be used.
enum connection_type {
    // Plain TCP connection
    tcp,
    // SSH connection
    ssh
};

/**
 * Application configuration structure.
 */
struct config {
  int   debug;
  int   no_syslog;

  int   support_bird;
  char *bird_socket_path;
  char *bird_roa_table;

  enum connection_type rtr_connection_type;
  char *rtr_host;
  char *rtr_port;
  char *rtr_ssh_username;
  char *rtr_ssh_hostkey_file;
  char *rtr_ssh_privkey_file;
  char *rtr_ssh_pubkey_file;
  int   rtr_refresh;
  int   rtr_expire;
  int   rtr_retry;
  
  int   support_mib;
  struct rpkiRtr_snmp_config  snmp_config;
};

/**
 * Checks the specified application configuration for errors.
 * @param
 * @return
 */
int config_check(const struct config *);

/**
 * Initializes the specified application configuration.
 * @param
 */
void config_init(struct config *);

#endif
