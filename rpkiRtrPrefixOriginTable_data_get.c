/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $ 
 *
 * $Id:$
 */
/*
 * standard Net-SNMP includes 
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/*
 * include our parent header 
 */
#include "rpkiRtrPrefixOriginTable.h"


/** @defgroup data_get data_get: Routines to get data
 *
 * These routine are used to get the value for individual objects. The
 * row context is passed, along with a pointer to the memory where the
 * value should be copied.
 *
 * @{
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table rpkiRtrPrefixOriginTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * RPKI-RTR-MIB::rpkiRtrPrefixOriginTable is subid 4 of rpkiRtrObjects.
 * Its status is Current.
 * OID: .1.3.6.1.2.1.218.1.4, length: 9
 */


/**
 * set mib index(es)
 *
 * @param tbl_idx mib index structure
 * @param rpkiRtrPrefixOriginAddressType_val
 * @param rpkiRtrPrefixOriginAddress_ptr
 * @param rpkiRtrPrefixOriginAddress_ptr_len
 * @param rpkiRtrPrefixOriginMinLength_val
 * @param rpkiRtrPrefixOriginMaxLength_val
 * @param rpkiRtrPrefixOriginASN_val
 * @param rpkiRtrPrefixOriginCacheServerId_val
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 *
 * @remark
 *  This convenience function is useful for setting all the MIB index
 *  components with a single function call. It is assume that the C values
 *  have already been mapped from their native/rawformat to the MIB format.
 */
int
rpkiRtrPrefixOriginTable_indexes_set_tbl_idx
    (rpkiRtrPrefixOriginTable_mib_index * tbl_idx,
     u_long rpkiRtrPrefixOriginAddressType_val,
     char *rpkiRtrPrefixOriginAddress_val_ptr,
     size_t rpkiRtrPrefixOriginAddress_val_ptr_len,
     u_long rpkiRtrPrefixOriginMinLength_val,
     u_long rpkiRtrPrefixOriginMaxLength_val,
     u_long rpkiRtrPrefixOriginASN_val,
     u_long rpkiRtrPrefixOriginCacheServerId_val)
{
    DEBUGMSGTL(("verbose:rpkiRtrPrefixOriginTable:rpkiRtrPrefixOriginTable_indexes_set_tbl_idx", "called\n"));

    /*
     * rpkiRtrPrefixOriginAddressType(1)/InetAddressType/ASN_INTEGER/long(u_long)//l/a/w/E/r/d/h 
     */
    tbl_idx->rpkiRtrPrefixOriginAddressType =
        rpkiRtrPrefixOriginAddressType_val;

    /*
     * rpkiRtrPrefixOriginAddress(2)/InetAddress/ASN_OCTET_STR/char(char)//L/a/w/e/R/d/h 
     */
    tbl_idx->rpkiRtrPrefixOriginAddress_len = sizeof(tbl_idx->rpkiRtrPrefixOriginAddress) / sizeof(tbl_idx->rpkiRtrPrefixOriginAddress[0]);     /* max length */
    /*
     * make sure there is enough space for rpkiRtrPrefixOriginAddress data
     */
    if ((NULL == tbl_idx->rpkiRtrPrefixOriginAddress) ||
        (tbl_idx->rpkiRtrPrefixOriginAddress_len <
         (rpkiRtrPrefixOriginAddress_val_ptr_len))) {
        snmp_log(LOG_ERR,
                 "not enough space for value (rpkiRtrPrefixOriginAddress_val_ptr)\n");
        return MFD_ERROR;
    }
    tbl_idx->rpkiRtrPrefixOriginAddress_len =
        rpkiRtrPrefixOriginAddress_val_ptr_len;
    memcpy(tbl_idx->rpkiRtrPrefixOriginAddress,
           rpkiRtrPrefixOriginAddress_val_ptr,
           rpkiRtrPrefixOriginAddress_val_ptr_len *
           sizeof(rpkiRtrPrefixOriginAddress_val_ptr[0]));

    /*
     * rpkiRtrPrefixOriginMinLength(3)/InetAddressPrefixLength/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/R/d/H 
     */
    tbl_idx->rpkiRtrPrefixOriginMinLength =
        rpkiRtrPrefixOriginMinLength_val;

    /*
     * rpkiRtrPrefixOriginMaxLength(4)/InetAddressPrefixLength/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/R/d/H 
     */
    tbl_idx->rpkiRtrPrefixOriginMaxLength =
        rpkiRtrPrefixOriginMaxLength_val;

    /*
     * rpkiRtrPrefixOriginASN(5)/InetAutonomousSystemNumber/ASN_UNSIGNED/u_long(u_long)//l/a/w/e/R/d/H 
     */
    tbl_idx->rpkiRtrPrefixOriginASN = rpkiRtrPrefixOriginASN_val;

    /*
     * rpkiRtrPrefixOriginCacheServerId(6)/UNSIGNED32/ASN_UNSIGNED/u_long(u_long)//l/A/w/e/R/d/h 
     */
    tbl_idx->rpkiRtrPrefixOriginCacheServerId =
        rpkiRtrPrefixOriginCacheServerId_val;


    return MFD_SUCCESS;
}                               /* rpkiRtrPrefixOriginTable_indexes_set_tbl_idx */

/**
 * @internal
 * set row context indexes
 *
 * @param reqreq_ctx the row context that needs updated indexes
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 *
 * @remark
 *  This function sets the mib indexs, then updates the oid indexs
 *  from the mib index.
 */
int
rpkiRtrPrefixOriginTable_indexes_set(rpkiRtrPrefixOriginTable_rowreq_ctx *
                                     rowreq_ctx,
                                     u_long
                                     rpkiRtrPrefixOriginAddressType_val,
                                     char
                                     *rpkiRtrPrefixOriginAddress_val_ptr,
                                     size_t
                                     rpkiRtrPrefixOriginAddress_val_ptr_len,
                                     u_long
                                     rpkiRtrPrefixOriginMinLength_val,
                                     u_long
                                     rpkiRtrPrefixOriginMaxLength_val,
                                     u_long rpkiRtrPrefixOriginASN_val,
                                     u_long
                                     rpkiRtrPrefixOriginCacheServerId_val)
{
    DEBUGMSGTL(("verbose:rpkiRtrPrefixOriginTable:rpkiRtrPrefixOriginTable_indexes_set", "called\n"));

    if (MFD_SUCCESS !=
        rpkiRtrPrefixOriginTable_indexes_set_tbl_idx(&rowreq_ctx->tbl_idx,
                                                     rpkiRtrPrefixOriginAddressType_val,
                                                     rpkiRtrPrefixOriginAddress_val_ptr,
                                                     rpkiRtrPrefixOriginAddress_val_ptr_len,
                                                     rpkiRtrPrefixOriginMinLength_val,
                                                     rpkiRtrPrefixOriginMaxLength_val,
                                                     rpkiRtrPrefixOriginASN_val,
                                                     rpkiRtrPrefixOriginCacheServerId_val))
        return MFD_ERROR;

    /*
     * convert mib index to oid index
     */
    rowreq_ctx->oid_idx.len = sizeof(rowreq_ctx->oid_tmp) / sizeof(oid);
    if (0 != rpkiRtrPrefixOriginTable_index_to_oid(&rowreq_ctx->oid_idx,
                                                   &rowreq_ctx->tbl_idx)) {
        return MFD_ERROR;
    }

    return MFD_SUCCESS;
}                               /* rpkiRtrPrefixOriginTable_indexes_set */




/** @} */
