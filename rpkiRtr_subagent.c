/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $ 
 */
/*
 * standard Net-SNMP includes 
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/library/large_fd_set.h>

/*
 * include our parent header 
 */
#include "rpkiRtr_subagent.h"
#include "rpkiRtrPrefixOriginTable.h"
#include "rpkiRtrCacheServerTable.h"

#include <signal.h>
#include <limits.h>
#include <errno.h>

#include "bird-rpki-client.h"

/*
 * If compiling within the net-snmp source code, this will trigger the feature
 * detection mechansim to ensure the agent_check_and_process() function
 * is left available even if --enable-minimialist is turned on.  If you
 * have configured net-snmp using --enable-minimialist and want to compile
 * this code externally to the Net-SNMP code base, then please add
 * --with-features="agent_check_and_process enable_stderrlog" to your
 * configure line.
 */
netsnmp_feature_require(agent_check_and_process)
netsnmp_feature_require(enable_stderrlog)


void
rpkiRtr_init_config(struct rpkiRtr_snmp_config *snmpConfig) {
  snmpConfig->D_debug            = 0;
  snmpConfig->debug_tokens       = NULL;
  snmpConfig->f_dont_fork        = 1;
  snmpConfig->H_config_usage     = 0;
  snmpConfig->M_master           = 0;
  snmpConfig->master_address     = NULL;
  snmpConfig->L_no_syslog        = 0;
  snmpConfig->x_agentx_socket    = 0;
  snmpConfig->agentx_socket      = NULL;
};

static void
usage(void)
{
    printf
        ("usage: rpkiRtrPrefixOriginTable [-D<tokens>] [-f] [-L] [-M] [-H] [LISTENING ADDRESSES]\n"
         "\t-f      Do not fork() from the calling shell.\n"
         "\t-DTOKEN[,TOKEN,...]\n"
         "\t\tTurn on debugging output for the given TOKEN(s).\n"
         "\t\tWithout any tokens specified, it defaults to printing\n"
         "\t\tall the tokens (which is equivalent to the keyword 'ALL').\n"
         "\t\tYou might want to try ALL for extremely verbose output.\n"
         "\t\tNote: You can't put a space between the -D and the TOKENs.\n"
         "\t-H\tDisplay a list of configuration file directives\n"
         "\t\tunderstood by the agent and then exit.\n"
         "\t-M\tRun as a normal SNMP Agent instead of an AgentX sub-agent.\n"
         "\t-x ADDRESS\tconnect to master agent at ADDRESS (default /var/agentx/master).\n"
         "\t-L\tDo not open a log file; print all messages to stderr.\n");
    exit(0);
}


int
rpkiRtr_start_subagent(struct rpkiRtr_snmp_config *snmpConfig)
{
    int    agentx_subagent = 1;
    int    dont_fork = 0, use_syslog = 0;
    char  *agentx_socket = NULL;

	/* process config parameters */

    if ( snmpConfig->D_debug ) {
      fprintf(stderr, "subagent: debug\n");
      debug_register_tokens(snmpConfig->debug_tokens);
      snmp_set_do_debugging(1);
    }
    if ( snmpConfig->f_dont_fork ) {
      dont_fork = 1;
    }    
    if ( snmpConfig->H_config_usage ) {
      fprintf(stderr, "subagent: usage\n");
      netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
			     NETSNMP_DS_AGENT_NO_ROOT_ACCESS, 1);
      /* register our .conf handlers */
      init_agent("bird-rpki-client");

      init_rpkiRtrPrefixOriginTable();
      init_rpkiRtrCacheServerTable();

      init_snmp("bird-rpki-client");

      fprintf(stderr, "Configuration directives understood:\n");
      read_config_print_usage("  ");
      exit(0);
    }    
    if ( snmpConfig->M_master ) {
      fprintf(stderr, "subagent: master\n");
      agentx_subagent = 0;
      char           *c, *astring;
      if ((c = netsnmp_ds_get_string(NETSNMP_DS_APPLICATION_ID,
				     NETSNMP_DS_AGENT_PORTS))) {
	astring = malloc(strlen(c) + 2 + strlen(snmpConfig->master_address));
	if (astring == NULL) {
	  fprintf(stderr, "malloc failure with master agent net addressv\n");
	  exit(1);
	}
	sprintf(astring, "%s,%s", c, snmpConfig->master_address);
	fprintf(stderr, "\nMAIN MAIN MAIN: setting address : %s : %s : '%s'\n\n",
		c, snmpConfig->master_address, astring);
	netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
			      NETSNMP_DS_AGENT_PORTS, astring);
	SNMP_FREE(astring);
      } else {
	fprintf(stderr, "\nMAIN MAIN MAIN: setting address '%s'\n\n",
		snmpConfig->master_address);
	netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
			      NETSNMP_DS_AGENT_PORTS,
			      snmpConfig->master_address);
      }
      DEBUGMSGTL(("snmpd/main", "port spec: %s\n",
		  netsnmp_ds_get_string(NETSNMP_DS_APPLICATION_ID,
					NETSNMP_DS_AGENT_PORTS)));
    }

    if ( snmpConfig->L_no_syslog ) {
      printf("setting syslog 0\n");
      use_syslog = 0;     /* use stderr */
    }
    if ( snmpConfig->x_agentx_socket ) {
      fprintf(stderr, "subagent: agentx \n");
      agentx_socket = snmpConfig->agentx_socket;
    }
    
	/* start engine */
	
    /* are we a agentx subagent?  */
    if (agentx_subagent) {
        /** make us a agentx client. */
        netsnmp_enable_subagent();
        if (NULL != agentx_socket)
            netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                                  NETSNMP_DS_AGENT_X_SOCKET,
                                  agentx_socket);
    }

    snmp_disable_log();
    if (use_syslog) {
        snmp_enable_calllog();
    }
    else {
        printf ("enabling stderrlog\n");
		snmp_enable_stderrlog();
    }
    
    /*
     * daemonize 
     */
    if (!dont_fork) {
      int   rc = netsnmp_daemonize(1, !use_syslog);
      /* return instead of exit */
      if (rc)
	return(1);
    }

    /*
     * initialize tcp/ip if necessary 
     */
    SOCK_STARTUP;

    /*
     * initialize the agent library 
     */
    init_agent("bird-rpki-client");

    /*
     * init mib code 
     */
    init_rpkiRtrPrefixOriginTable();
    init_rpkiRtrCacheServerTable();

    /*
     * read rpkiRtrPrefixOriginTable.conf files. 
     */
    init_snmp("bird-rpki-client");

    /*
     * If we're going to be a snmp master agent, initial the ports 
     */
    if (!agentx_subagent)
	  /* open the port to listen on (defaults to udp:161) */
	  init_master_agent();

    /* snmp wants to control these, reset them here */
    signal(SIGTERM, bird_rpki_stop_servers);
    signal(SIGINT,  bird_rpki_stop_servers);

    /*
     * In case we recevie a request to stop (kill -TERM or kill -INT) 
     */
    bbc_snmpd_keep_running = 1;

    /*
     * you're main loop here... 
     */
    int fds = 0, block = 1, count;
    netsnmp_large_fd_set fdset;

    while (bbc_snmpd_keep_running) {

      struct timeval  timeout = { LONG_MAX, 0 }, *tvp = &timeout;

      fds   = 0;
      block = 1;
      count = 0;

      netsnmp_large_fd_set_init(&fdset, FD_SETSIZE);
      NETSNMP_LARGE_FD_ZERO(&fdset);

      /* if snmp alarms are found block will be set to '0' and tvp
       * will be set to the alarm time */
      snmp_select_info2(&fds, &fdset, tvp, &block);

      count = netsnmp_large_fd_set_select( fds, &fdset, NULL, NULL,
					   (block ? NULL : tvp) );

      if (count > 0) {
        /*
         * packets found, process them 
         */
	/* printf("snmpd: block: %d timeout: %d:%d,  %s\n", block, */
	/*        (int)tvp.tv_sec, (int)tvp.tv_usec, bbc_timestamp() ); */
	pthread_mutex_lock(&bgpsec_bc_mutex);
        snmp_read2(&fdset);
	pthread_mutex_unlock(&bgpsec_bc_mutex);
      }
      else {
        switch (count) {
        case 0:
	  snmp_timeout();
	  break;
        case -1:
	  if (errno != EINTR) {
	    snmp_log_perror("select");
	  }
	  break;
        default:
	  snmp_log(LOG_ERR, "select returned %d\n", count);
	  break;
        }
      }             /* endif -- count>0 */
      /*
       * see if persistent store needs to be saved
       */
      snmp_store_if_needed();
      /*
       * Run requested alarms.  
       */
      run_alarms();

      netsnmp_check_outstanding_agent_requests();

      netsnmp_large_fd_set_cleanup(&fdset);

    } /*  while (bbc_snmpd_keep_running) */

    /*
     * at shutdown time 
     */
    snmp_shutdown("bird-rpki-client");
    SOCK_CLEANUP;

    return EXIT_SUCCESS;
}
