/*
 * Note: this file originally auto-generated by mib2c using
 *       version $ of $
 *
 * $Id:$
 */
#ifndef RPKIRTRPREFIXORIGINTABLE_DATA_ACCESS_H
#define RPKIRTRPREFIXORIGINTABLE_DATA_ACCESS_H

#ifdef __cplusplus
extern          "C" {
#endif


    /*
     *********************************************************************
     * function declarations
     */

    /*
     *********************************************************************
     * Table declarations
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


    int            
        rpkiRtrPrefixOriginTable_init_data
        (rpkiRtrPrefixOriginTable_registration *
         rpkiRtrPrefixOriginTable_reg);


    /*
     * TODO:180:o: Review rpkiRtrPrefixOriginTable cache timeout.
     * The number of seconds before the cache times out
     */
#define RPKIRTRPREFIXORIGINTABLE_CACHE_TIMEOUT   60

    void           
        rpkiRtrPrefixOriginTable_container_init(netsnmp_container **
                                                container_ptr_ptr,
                                                netsnmp_cache * cache);
    void           
        rpkiRtrPrefixOriginTable_container_shutdown(netsnmp_container *
                                                    container_ptr);

    int            
        rpkiRtrPrefixOriginTable_container_load(netsnmp_container *
                                                container);
    void           
        rpkiRtrPrefixOriginTable_container_free(netsnmp_container *
                                                container);

    int             rpkiRtrPrefixOriginTable_cache_load(netsnmp_container *
                                                        container);
    void            rpkiRtrPrefixOriginTable_cache_free(netsnmp_container *
                                                        container);

    /*
     ***************************************************
     ***             START EXAMPLE CODE              ***
     ***---------------------------------------------***/
    /*
     *********************************************************************
     * Since we have no idea how you really access your data, we'll go with
     * a worst case example: a flat text file.
     */
#define MAX_LINE_SIZE 256
    /*
     ***---------------------------------------------***
     ***              END  EXAMPLE CODE              ***
     ***************************************************/
    int            
        rpkiRtrPrefixOriginTable_row_prep
        (rpkiRtrPrefixOriginTable_rowreq_ctx * rowreq_ctx);



#ifdef __cplusplus
}
#endif
#endif                          /* RPKIRTRPREFIXORIGINTABLE_DATA_ACCESS_H */
