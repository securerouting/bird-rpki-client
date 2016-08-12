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


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <rtrlib/rtrlib.h>
#include <rtrlib/rtr_mgr.h>

#include <sys/socket.h>
#include <sys/unistd.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>

#include "cli.h"
#include "config.h"

#include "rpkiRtr_subagent.h"
#include "bird-rpki-client.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/library/data_list.h>
#include <net-snmp/library/container.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "rpkiRtrPrefixOriginTable_interface.h"

#define CMD_EXIT "exit"

// Command line config options
struct config bbc_config;

// program PId
static int  bbc_pid = 0;

// Socket to BIRD.
static int bird_socket = -1;

// Buffer for BIRD commands.
static char *bird_command = 0;

// Length of buffer for BIRD commands.
static size_t bird_command_length = -1;

// "add roa" BIRD command "table" part. Defaults to an empty string
// and becomes "table " + config->bird_roa_table if provided.
static char *bird_add_roa_table_arg = "";

/* RTR manager config, somewhat messy due to pointers within pointers
 * within arrays in rtlib and how it frees data.*/
/* global: struct rtr_mgr_config *bgpsec_bc_rtr_config */
#define BGPSECBC_GROUPLEN 1
#define BGPSECBC_SOCKLEN  1

static struct rtr_mgr_group   bgpsec_bc_rtr_groups[BGPSECBC_GROUPLEN]; 

#define MAXPATHSIZE 512
#define MAXSMALLBUF 512
char* ROUTER_KEY_PATH = "/usr/share/bird/bgpsec-keys";
char* ROUTER_KEY_EXT  = ".0.key";


static char* bbc_timestamp(void) {
  static char     datestamp[41];
  struct timeval  tv;
  struct timezone tz;
  struct tm       tm;
  
  if( (gettimeofday(&tv, &tz) == 0) &&
      (localtime_r(&tv.tv_sec, &tm) != NULL) ) {
    snprintf(datestamp, 40,
	     "%04d%02d%02d %02d:%02d:%02d:%06ld",
	     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	     tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
  }
  else {
    snprintf(datestamp, 40, "(%jd): ", (intmax_t) time(0));
  }

  return (char*)&datestamp;
}


/**
 *  Output function.
 */
void  bbc_print(int level, const char *frmt, ...) {
    va_list     argptr;
    static char vbuff[251], buff[311];

    va_start(argptr, frmt);
    vsnprintf(vbuff, 250, frmt, argptr);

    snprintf(buff, 310,
	     "bird-rpki-client %d %s : %s",
	     bbc_pid, bbc_timestamp(), vbuff);
    
    if ( (bbc_config.debug) || (level <= LOG_INFO)   )  {
      if ( buff[strlen(buff)-1] == '\n' ) { fprintf(stderr, "%s", buff);   }
      else                                { fprintf(stderr, "%s\n", buff); }
    }

    /* do not log debug */
    if ( (0 == bbc_config.no_syslog) &&
         (level <= LOG_INFO)             )  {
      syslog(level, "%s", buff);
    }
}


/**
 * Performs cleanup on resources allocated by `init()`.
 */
void cleanup(void) {
  closelog();
}


/**
 * Frees memory allocated with the " table <bird_roa_table>" clause for the
 * "add roa" BIRD command.
 */
void cleanup_bird_add_roa_table_arg(void) {
    // If the buffer is "", it has never been changed, thus there is
    // no malloc'd buffer.
    if (strcmp(bird_add_roa_table_arg, "") != 0)
        free(bird_add_roa_table_arg);
}

/**
 * Frees memory allocated with the BIRD command buffer.
 */
void cleanup_bird_command(void) {
    if (bird_command) {
        free(bird_command);
        bird_command = 0;
        bird_command_length = -1;
    }
}


/**
 * Initializes the application prerequisites.
 */
void init(void) {
  bbc_pid = getpid();
  openlog(" ", LOG_CONS, LOG_DAEMON);
}


/**
 * Connects to the BIRD daemon listening at the specified socket. Returns the
 * socket on success or -1 on failure.
 * @param socket_path
 * @return
 */
int bbc_bird_connect(const char *socket_path) {
    // Result value containing the socket to the BIRD.
    int bird_socket = -1;

    // Socket address to the BIRD.
    struct sockaddr_un addr;

    // Check socket path length.
    if (strlen(socket_path) >= sizeof addr.sun_path) {
        bbc_print(LOG_CRIT, "Socket path too long");
        return -1;
    }

    // Create socket and bail out on error.
    bird_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bird_socket < 0) {
        bbc_print(LOG_CRIT, "Socket creation error: %m");
        return -1;
    }

    // Create socket address.
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, socket_path);

    // Try to connect to BIRD.
    if (connect(bird_socket, (struct sockaddr *) &addr, sizeof addr) == -1) {
        bbc_print(LOG_CRIT, "BIRD connection to %s failed: %m", socket_path);
        close(bird_socket);
        return -1;
    }

    // Return socket.
    return bird_socket;
}


/**
 * Creates and populates the "add roa" command's "table" argument buffer.
 * @param bird_roa_table
 */
void init_bird_add_roa_table_arg(char *bird_roa_table) {
    // Size of the buffer (" table " + <roa_table> + \0).
    const size_t length = (8 + strlen(bird_roa_table)) * sizeof (char);

    // Allocate buffer.
    bird_add_roa_table_arg = malloc(length);

    // Populate buffer.
    snprintf(bird_add_roa_table_arg, length, " table %s", bird_roa_table);
}

/**
 * Creates the buffer for the "add roa" command.
 */
void init_bird_command(void) {
    // Size of the buffer ("add roa " + <addr> + "/" + <minlen> + " max " +
    // <maxlen> + " as " + <asnum> + <bird_add_roa_table_cmd> + \0)
    bird_command_length = (
        8 + // "add roa "
        39 + // maxlength of IPv6 address
        1 + // "/"
        3 + // minimum length, "0" .. "128"
        5 + // " max "
        3 + // maximum length, "0" .. "128"
        4 + // " as "
        10 + // asnum, "0" .. "2^32 - 1" (max 10 chars)
        strlen(bird_add_roa_table_arg) + // length of fixed " table " + <table>
        1 // \0
    ) * sizeof (char);

    // Allocate buffer.
    bird_command = malloc(bird_command_length);
}


/* Router connection */
struct rtr_mgr_config *router_connect(const struct config     *config,
				      const pfx_update_fp     pfx_callback,
				      const spki_update_fp    spki_callback,
				      const rtr_mgr_status_fp status_callback)
{
    /* Globals:
       static struct rtr_mgr_group   bgpsec_bc_rtr_groups[];
    */

    struct rtr_mgr_config *rtr_mgr_conf;
    struct tr_tcp_config   tcp_config;
#ifdef RTRLIB_HAVE_LIBSSH
    struct tr_ssh_config   ssh_config;
#endif


    struct tr_socket   *tr_sock = malloc(sizeof(struct tr_socket));
    if ( NULL == tr_sock )  return NULL;
    struct rtr_socket *rtr_sock = malloc(sizeof(struct rtr_socket));
    if ( NULL == rtr_sock ) return NULL;

    rtr_sock->tr_socket = tr_sock;

    if(config->rtr_connection_type == tcp){
        tcp_config = (struct tr_tcp_config) { config->rtr_host, 
					      config->rtr_port,
	                                      0 };
        if (TR_SUCCESS != tr_tcp_init(&tcp_config, tr_sock)) {
	  bbc_print(LOG_ERR, "Error: Failed to init TCP");
	  return NULL;
	}
    }
#ifdef RTRLIB_HAVE_LIBSSH
    else{
      unsigned int iport = atoi(config->rtr_port);
      ssh_config = (struct tr_ssh_config) { config->rtr_host,
					    iport,
					    config->rtr_ssh_username,
					    config->rtr_ssh_hostkey_file,
					    config->rtr_ssh_privkey_file };
      tr_ssh_init(&ssh_config, tr_sock);
    }
#endif
    


    bgpsec_bc_rtr_groups[0].sockets_len = BGPSECBC_SOCKLEN;

    bgpsec_bc_rtr_groups[0].sockets     =
      malloc(sizeof(struct rtr_socket*) * (BGPSECBC_SOCKLEN));
    if ( NULL == bgpsec_bc_rtr_groups[0].sockets ) return NULL;

    bgpsec_bc_rtr_groups[0].sockets[0]  = rtr_sock;
    bgpsec_bc_rtr_groups[0].preference  = 1;

    int rtr_status = rtr_mgr_init(
      &rtr_mgr_conf, bgpsec_bc_rtr_groups, BGPSECBC_GROUPLEN, 
      config->rtr_refresh, config->rtr_expire, config->rtr_retry,
      pfx_callback, 
      spki_callback,
      status_callback,
      NULL);

    if (rtr_status != RTR_SUCCESS) {
      if (rtr_status == RTR_INVALID_PARAM) {
	bbc_print(LOG_ERR, "Error: Invalid Parametor to rtr_mgr_init");
      }
      else if (rtr_status == RTR_ERROR) {
	bbc_print(LOG_ERR, "Error: General error from rtr_mgr_init");
      }
      return NULL;
    }

    rtr_status = rtr_mgr_start(rtr_mgr_conf);
    if (rtr_status != RTR_SUCCESS) {
	bbc_print(LOG_ERR, "Error: starting RTR Manager");
    }

    // Return RTR manager config.
    return rtr_mgr_conf;
}  /* router_connect */


void router_close(struct rtr_mgr_config *rtr_mgr_config) {

  // Stop the RTR manager.
  rtr_mgr_stop(rtr_mgr_config);

  // Free RTR manager internal structures.
  rtr_mgr_free(rtr_mgr_config);

  // Close and free all sockets from all groups.
  /* tr_close( bgpsec_bc_rtr_groups[0].sockets[BGPSECBC_SOCKLEN]->tr_socket ); */
  /* tr_free(  bgpsec_bc_rtr_groups[0].sockets[BGPSECBC_SOCKLEN]->tr_socket ); */

  /* free( bgpsec_bc_rtr_groups[0].sockets[BGPSECBC_SOCKLEN]->tr_socket ); */
  /* free( bgpsec_bc_rtr_groups[0].sockets[BGPSECBC_SOCKLEN] ); */
  /* free( bgpsec_bc_rtr_groups[0].sockets ); */

} /* router_close */


/**
 * callback function for RTRLib that updates the status
 **/
static void status_callback
  (const struct rtr_mgr_group *group __attribute__((unused)),
   enum rtr_mgr_status        mgr_status, 
   const struct rtr_socket    *rtr_sock,
   void *data __attribute__((unused)))
{
  bbc_print(LOG_DEBUG, "status_callback:");

  bbc_print(LOG_INFO,
	    "status update: RTR-socket: \'%s\'/\'%s\'\n",
	    rtr_state_to_str(rtr_sock->state),
	    rtr_mgr_status_to_str(mgr_status));
}


/* 
 * mod_snmp_prefix_cache 
 * 
 * Creates a new row index and adds/deletes that index from the MIB
 * cache.
 */
static int  mod_snmp_prefix_cache(struct pfx_table        *table, 
				  const struct pfx_record pfx_record, 
				  const bool              added)  {
  /* bbc_print(LOG_DEBUG, "mod_snmp_prefix_cache callback:"); */
  netsnmp_container *data = 0;

  if (NULL == (data = rpkiRtrPrefixOriginTable_container_get())) {
    bbc_print(LOG_ERR,
	   "mod_snmp_prefix_cache callback: unable to get container\n");
    return 0;
  }
  
  rpkiRtrPrefixOriginTable_rowreq_ctx *rowreq_ctx;
  
  /*
   * rpkiRtrPrefixOriginAddressType(1)
   * InetAddressType/ASN_INTEGER/long(u_long)//l/a/w/E/r/d/h
   */
  u_long  rpkiRtrPrefixOriginAddressType = INETADDRESSTYPE_IPV4;
  size_t  rpkiRtrPrefixOriginAddress_len = 4;
  /*
   * rpkiRtrPrefixOriginAddress(2)
   * InetAddress/ASN_OCTET_STR/char(char)//L/a/w/e/R/d/h
   */
  /** 128 - 1(entry) - 1(col) - 5(other indexes) = 110 */
  char    rpkiRtrPrefixOriginAddress[16];
  if ( LRTR_IPV4 == pfx_record.prefix.ver ) {
    rpkiRtrPrefixOriginAddressType = INETADDRESSTYPE_IPV4;
    rpkiRtrPrefixOriginAddress_len = 4;
    memcpy(rpkiRtrPrefixOriginAddress, &(pfx_record.prefix.u.addr4), 4);
  }
  else if ( LRTR_IPV6 == pfx_record.prefix.ver ) {
    rpkiRtrPrefixOriginAddressType = INETADDRESSTYPE_IPV6;
    rpkiRtrPrefixOriginAddress_len = 16;
    memcpy(rpkiRtrPrefixOriginAddress, &(pfx_record.prefix.u.addr6), 16);
  }
  else {
    bbc_print(LOG_WARNING,
	      "mod_snmp_prefix_cache callback: unhandled ip version: %d",
	      pfx_record.prefix.ver);
    return 0;
  }

  /*
   * rpkiRtrPrefixOriginMinLength(3)
   * InetAddressPrefixLength/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/R/d/H
   */
  u_long  rpkiRtrPrefixOriginMinLength = pfx_record.min_len;
  /*
   * rpkiRtrPrefixOriginMaxLength(4)
   * InetAddressPrefixLength/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/R/d/H
   */
  u_long  rpkiRtrPrefixOriginMaxLength = pfx_record.max_len;
  /*
   * rpkiRtrPrefixOriginASN(5)
   * InetAutonomousSystemNumber/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/R/d/H
   */
  u_long  rpkiRtrPrefixOriginASN = pfx_record.asn;
  /*
   * rpkiRtrPrefixOriginCacheServerId(6)
   * UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/w/e/R/d/h */
  /* XXX needs to be connected to cache server value */
  u_long          rpkiRtrPrefixOriginCacheServerId = 0;
    
  /*
   * set indexes in new rpkiRtrPrefixOriginTable rowreq context.
   */
  pthread_mutex_lock(&bgpsec_bc_mutex);
  rowreq_ctx = rpkiRtrPrefixOriginTable_allocate_rowreq_ctx();
  if (NULL == rowreq_ctx) {
    bbc_print(LOG_ERR,
	   "mod_snmp_prefix_cache: rowreq_ctx memory allocation failed\n");
    return 0;
  }
  if (MFD_SUCCESS !=
      rpkiRtrPrefixOriginTable_indexes_set(rowreq_ctx,
					   rpkiRtrPrefixOriginAddressType,
					   rpkiRtrPrefixOriginAddress,
					   rpkiRtrPrefixOriginAddress_len,
					   rpkiRtrPrefixOriginMinLength,
					   rpkiRtrPrefixOriginMaxLength,
					   rpkiRtrPrefixOriginASN,
					   rpkiRtrPrefixOriginCacheServerId))
    {
      bbc_print(LOG_ERR,
	     "mod_snmp_prefix_cache: error setting index while loading "
	     "rpkiRtrPrefixOriginTable index.\n");
      rpkiRtrPrefixOriginTable_release_rowreq_ctx(rowreq_ctx);
      return 0;
    }
  
  /*
   * insert into table container
   */
  if (added) {
    CONTAINER_INSERT((netsnmp_container *)data, rowreq_ctx);
  }
  else {
    CONTAINER_REMOVE((netsnmp_container *)data, rowreq_ctx);
  }
  pthread_mutex_unlock(&bgpsec_bc_mutex);

  return 1;
}  /* mod_snmp_prefix_cache */


/**
 * Callback function for RTRLib that receives PFX records, translates them to
 * BIRD `add roa` commands, sends them to the BIRD server and fetches the
 * answer.
 *
 * If SNMP is enabled, updates the prefix in the RPKI-RTR-MIB.
 *
 * @param table
 * @param record
 * @param added
 */
static void pfx_callback(struct pfx_table        *table, 
			 const struct pfx_record record, 
			 const bool              added)  {
    static int count = 0;
    count++;

    if ( count >= 1000 ) {
      count = 0;
      bbc_print(LOG_DEBUG, "pfx_callback:");
    }

    if ( bbc_config.support_bird ) {
      // IP address buffer.
      static char ip_addr_str[INET6_ADDRSTRLEN];

      // Buffer for BIRD response.
      static char bird_response[200];

      // Fetch IP address as string.
      lrtr_ip_addr_to_str(&(record.prefix), ip_addr_str, sizeof(ip_addr_str));

      // Write BIRD command to buffer.
      if (
        snprintf(
	  bird_command,
	  bird_command_length,
	  "%s roa %s/%d max %d as %d%s\n",
	  added ? "add" : "delete",
	  ip_addr_str,
	  record.min_len,
	  record.max_len,
	  record.asn,
	  bird_add_roa_table_arg
	  )
        >= bird_command_length
	) {
        bbc_print(LOG_ERR, "BIRD command too long.");
        return;
      }

      // Log the BIRD command and send it to the BIRD server.
      bbc_print(LOG_DEBUG, "To BIRD: %s", bird_command);
      if ( strlen(bird_command) !=
	   write(bird_socket, bird_command, strlen(bird_command)) ) {
	bbc_print(LOG_ERR,
	       "Error: pfx_callback: failed sending command to BIRD socket");
      }

      // Fetch the answer and log.
      bird_response[read(bird_socket, bird_response, sizeof bird_response)] = 0;
      bbc_print(LOG_DEBUG, "From BIRD: %s", bird_response);
    }
    
    // If the MIB is supported, update the MIB cache with the prefix info
    if ( bbc_config.support_mib ) {
      mod_snmp_prefix_cache(table, record, added);
    }

}


static int write_router_key(const struct spki_record spki_rec)  {
  char file_name[MAXPATHSIZE+1];

  int fn_len = 0, i = 0;
//  int ski_len = 0;

  bbc_print(LOG_DEBUG, "write_router_key:");

  // Check Buffer Size
  if ( ( strlen(ROUTER_KEY_PATH) + strlen(ROUTER_KEY_EXT) + 
	 (2 * sizeof(spki_rec.ski)) + 2 )
       >= MAXPATHSIZE ) {
    // not enough buffer space for file name
    bbc_print(LOG_ERR, "Error: not enough buffer space for file name for key \'%s/asn.ski%s\'",
	   ROUTER_KEY_PATH, ROUTER_KEY_EXT);
    return(0);
  }

  fn_len = snprintf(file_name, MAXPATHSIZE, "%s/%d.",
		    ROUTER_KEY_PATH, spki_rec.asn);
  
  while ( ( fn_len < (MAXPATHSIZE - strlen(ROUTER_KEY_EXT)) ) && 
	  ( i < sizeof(spki_rec.ski) ) )  {
    fn_len += snprintf((file_name+fn_len), (MAXPATHSIZE-fn_len),
		       "%02X", spki_rec.ski[i]);
    i++;
  }
  fn_len += snprintf((file_name+fn_len), (MAXPATHSIZE-fn_len), "%s",
		     ROUTER_KEY_EXT);


  FILE *kfd = fopen(file_name,"w");
  
  if ( NULL == kfd ) {
    bbc_print(LOG_ERR,
	    "Error: failure to open router public key file for writing: \'%s\'\n",
	   file_name);
    return(0);
  }

  if ( SPKI_SIZE > fwrite(spki_rec.spki, sizeof(uint8_t), SPKI_SIZE, kfd) ) {
    bbc_print(LOG_WARNING, "Error: failure to write to router key to file: \'%s\'", file_name);
    fclose(kfd);
    unlink(file_name);
    return(0);
  }

  fclose(kfd);
  return(1);
} // static int write_router_key(struct spki_record *spki_rec)


static void spki_callback(struct spki_table* s __attribute__((unused)), 
			  const struct spki_record record, 
			  const bool               added)  {
    char c;
    if(added)  c = '+';
    else       c = '-';

    bbc_print(LOG_DEBUG, "spki_callback: AS: %d", record.asn);

    if ( bbc_config.support_bird ) {

      char buf[MAXSMALLBUF+1];
      char *bptr = buf;
      int  len = 0;
      memset(bptr,'\0',MAXSMALLBUF);

      len += snprintf(bptr, (MAXSMALLBUF-len), "%c ",c);
      bptr = buf+len;
      len += snprintf(bptr, (MAXSMALLBUF-len), "ASN:  %u\n", record.asn);
      bptr = buf+len;

      int size = sizeof(record.ski);
      len += snprintf(bptr, (MAXSMALLBUF-len), "SKI:%d: ", size);
      bptr = buf+len;

      int i;
      for(i = 0;((i<size) && (len<MAXSMALLBUF));i++){
	len += snprintf(bptr,  (MAXSMALLBUF-len), "%02X", record.ski[i]);
	bptr = buf+len;
      }
      len += snprintf(bptr,  (MAXSMALLBUF-len), "\n\n");
      bptr = buf+len;

      i = 0; size = sizeof(record.spki);
      len += snprintf(bptr, (MAXSMALLBUF-len), "SPKI:%d:\n      ", size);
      bptr = buf+len;

      for(i = 0;((i<size) && (len<MAXSMALLBUF));i++){
	if(i % 20 == 0 && i != 0) {
	  len += snprintf(bptr,  (MAXSMALLBUF-len), "\n      ");
	  bptr = buf+len;
	}
	len += snprintf(bptr,  (MAXSMALLBUF-len), "%02X", record.spki[i]);
	bptr = buf+len;
      }
      len += snprintf(bptr,  (MAXSMALLBUF-len), "\nlength:%d\n",len);
      bptr = buf+len;
      buf[MAXSMALLBUF] = '\0';

      bbc_print(LOG_DEBUG, "spki_callback:\n%s", buf);

      if (added) {
	if ( 0 == write_router_key(record) ) {
	  bbc_print(LOG_ERR, "ERROR: spki: unable to write key file");
	}
	else {
	  bbc_print(LOG_DEBUG, "spki: successfully wrote key file");
	}
      }
    }
} // static void spki_callback


/**
 *  bird_rpki_shutown
 *  any rtrlib/snmpd cleanup
 */
void bird_rpki_shutdown(void) {
  bbc_print(LOG_WARNING, "Shutting down");

  // Clean up RTRLIB memory.
  if (bgpsec_bc_rtr_config) {
    router_close(bgpsec_bc_rtr_config);
  }

  // Close BIRD socket.
  if ( bbc_config.support_bird ) {
    close(bird_socket);
  }
  
  // cleanup bird-rpki-client
  // Cleanup memory.
  cleanup_bird_command();
  cleanup_bird_add_roa_table_arg();

  // Cleanup framework.
  cleanup();

} // bird_rpki_shutdown


void bird_rpki_client_shutdown(void) {
  bird_rpki_stop_servers(1);
}


/********************  MAIN MAIn MAIN  ********************/

/**
 * Entry point to the BIRD RTRLib integration application.
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[]) {
    // Main configuration.
    // config is global for the prefix callback routine

    // Buffer for commands and its length.
    size_t command_len = 0;
    char *command;
    
    // Initialize variables.
    config_init(&bbc_config);

    // Initialize framework.
    init();

    // Initialize mutex.
    if(pthread_mutex_init(&bgpsec_bc_mutex, NULL) != 0) {
        printf("Error: bird_rpki_client: Failed to initiliaze mutex\n");
        cleanup();
        return EXIT_FAILURE;
    }

    
    // Parse CLI arguments into config and bail out on error.
    if (!parse_cli(argc, argv, &bbc_config)) {
        cleanup();
        return EXIT_FAILURE;
    }

    // Check config.
    if (!config_check(&bbc_config)) {
        cleanup();
        return EXIT_FAILURE;
    }

    // if we are supporting bird
    if ( bbc_config.support_bird ) {
      // Setup BIRD ROA table command argument.
      if (bbc_config.bird_roa_table) {
        init_bird_add_roa_table_arg(bbc_config.bird_roa_table);
      }

      // Setup BIRD command buffer.
      init_bird_command();

      // Try to connect to BIRD and bail out on failure.
      bird_socket = bbc_bird_connect(bbc_config.bird_socket_path);
      if (bird_socket == -1) {
        cleanup();
        return EXIT_FAILURE;
      }
    }
    
    // connect to RPKI-RTR server
    bgpsec_bc_rtr_config = router_connect(&bbc_config, 
					  &pfx_callback,
					  &spki_callback,
					  &status_callback);

    // Bail out if connection cannot be established.
    if (!bgpsec_bc_rtr_config) {
      bbc_print(LOG_ERR, "Error: failed to connect to RPKI-RTR server!");
      bird_rpki_shutdown();
      return EXIT_FAILURE;
    };

    // Initiate SNMP subagent?
    if ( bbc_config.support_mib ) {
      bbc_print(LOG_WARNING, "Started with MIB support");
      if ( !rpkiRtr_start_subagent(&(bbc_config.snmp_config)) ) {
	bbc_print(LOG_ERR, "Error: failed to start SNMP agent");
	bird_rpki_shutdown();
	return EXIT_FAILURE;
      }
    }
    else {
      bbc_print(LOG_WARNING, "Started with no MIB support");
    }

    // set interrupt/terminate signal handling
    bbc_rtrlib_keep_running = 1;
    signal(SIGTERM, bird_rpki_stop_servers);
    signal(SIGINT,  bird_rpki_stop_servers);

    // Server loop. Read commands from stdin.
    while ( bbc_rtrlib_keep_running ) {
      fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
      if ( (getline(&command, &command_len, stdin) == -1) ) {
	if ( EAGAIN != errno ) {
	  bbc_print(LOG_WARNING, "getline error: %d: %s\n",
		    errno, strerror(errno));
	}
      }
      else if ( (strncmp(command, CMD_EXIT, strlen(CMD_EXIT)) == 0) )  {
	bbc_print(LOG_INFO, "Exiting");
	bird_rpki_client_shutdown();
      }
      // process commands
      sleep(1);
    }

    bbc_snmpd_keep_running  = 0;
    bird_rpki_shutdown();
    
    /* return EXIT_SUCCESS; */
    exit(0);
}
