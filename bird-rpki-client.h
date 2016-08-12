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


#ifndef BIRDRPKICLIENT_H
#define BIRDRPKICLIENT_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <rtrlib/rtrlib.h>
#include <signal.h>
#include "rpkiRtr_subagent.h"

/* XXX
   For direct socket access, need access routinse in rtrlib 
*/

  struct tr_tcp_socket {
    int socket;
    struct tr_tcp_config config;
    char *ident;
  };

  struct rtr_mgr_config *bgpsec_bc_rtr_config;
  pthread_mutex_t        bgpsec_bc_mutex;
  
  // signal shutdown info 
  static int  bbc_rtrlib_keep_running = 0;

  void bird_rpki_client_shutdown(void);

  static void bird_rpki_stop_servers(int a)
  {
    bbc_rtrlib_keep_running = 0;
    /* from rpkiRtr_subagent.h */
    bbc_snmpd_keep_running  = 0;
  }



#ifdef __cplusplus
}
#endif

#endif                          /* BIRDRPKICLIENT_H */

