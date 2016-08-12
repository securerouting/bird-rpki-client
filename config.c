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


#include <stdio.h>
#include <string.h>

#include "config.h"

/**
 * Checks the specified application config for errors. Returns `1` if it has no
 * errors, or `0` otherwise.
 * @param config
 * @return
 */
int config_check(const struct config *config) {
  // if supporting  bird
  if (0 != config->support_bird)  {
    // Check BIRD control socket path availability.
    if (!config->bird_socket_path) {
      fprintf(stderr, "Missing path to BIRD control socket.\n");
      return 0;
    }
  }
  // Check RTR host availability.
  if (!config->rtr_host) {
    fprintf(stderr, "Missing RTR server host.\n");
    return 0;
  }

  // Check RTR port availability.
  if (!config->rtr_port) {
    fprintf(stderr, "Missing RTR server port.\n");
    return 0;
  }

  // Checks to be done for SSH connections.
  if (config->rtr_connection_type == ssh) {
    // Check SSH username availability.
    if (!config->rtr_ssh_username) {
      fprintf(stderr, "Missing SSH username.\n");
      return 0;
    }
  }

  // Return success.
  return 1;
}

/**
 * Initializes the specified application configuration.
 * @param config
 */
void config_init(struct config *config) {
  // Reset memory.
  memset(config, 0, sizeof (struct config));

  config->debug     = 0;
  config->no_syslog = 0;

  // default to suporting BIRD
  config->support_bird = 1;
  
  // Default connection type is TCP.
  config->rtr_connection_type = tcp;
  config->rtr_refresh         = BIRD_RTRLIB_DEFAULT_RTR_REFRESH_RATE;
  config->rtr_expire          = BIRD_RTRLIB_DEFAULT_RTR_EXPIRE_RATE;
  config->rtr_retry           = BIRD_RTRLIB_DEFAULT_RTR_RETRY_RATE;    

  rpkiRtr_init_config(&(config->snmp_config));
}
