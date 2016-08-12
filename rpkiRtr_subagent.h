#ifndef RPKIRTRPREFIXORIGINTABLE_SUBAGENT_H
#define RPKIRTRPREFIXORIGINTABLE_SUBAGENT_H

#ifdef __cplusplus
extern          "C" {
#endif

  struct rpkiRtr_snmp_config {
    int   D_debug;
    char *debug_tokens;
    int   f_dont_fork;
    int   H_config_usage;
    int   M_master;
    char *master_address;
    int   L_no_syslog;
    int   x_agentx_socket;
    char *agentx_socket;
  };


  int
  rpkiRtr_start_subagent(struct rpkiRtr_snmp_config *snmpConfig);

  int      bbc_snmpd_keep_running;

  void
  rpkiRtr_init_config(struct rpkiRtr_snmp_config *snmpConfig);

#ifdef __cplusplus
}
#endif

#endif
