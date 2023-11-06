/*
 * smf_ue.h
 *
 * 
 */

#ifndef _OpenAPI_smf_ue_H_
#define _OpenAPI_smf_ue_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "../../../crypt/ogs-crypt.h"
#include "smf_sess.h"

// #include "../../ogs-sbi.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct OpenAPI_smf_ue_s OpenAPI_smf_ue_t;
typedef struct OpenAPI_smf_ue_s {
    // ogs_lnode_t lnode;

    // /* SUPI */
    char *supi;

    // /* IMSI */
    // uint8_t imsi[OGS_MAX_IMSI_LEN];
    // int imsi_len;
    // char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    // /* MSISDN */
    // uint8_t msisdn[OGS_MAX_MSISDN_LEN];
    // int msisdn_len;
    // char msisdn_bcd[OGS_MAX_MSISDN_BCD_LEN+1];

    // /* IMEI */
    // uint8_t imeisv[OGS_MAX_IMEISV_LEN];
    // int imeisv_len;
    // char  imeisv_bcd[OGS_MAX_IMEISV_BCD_LEN+1];

    // ogs_list_t sess_list
    OpenAPI_list_t *sess_list;
} OpenAPI_smf_ue_t;

OpenAPI_smf_ue_t *OpenAPI_smf_ue_create(
    // ogs_lnode_t lnode;

    // /* SUPI */
    char *supi,

    // /* IMSI */
    // uint8_t imsi[OGS_MAX_IMSI_LEN];
    // int imsi_len;
    // char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    // /* MSISDN */
    // uint8_t msisdn[OGS_MAX_MSISDN_LEN];
    // int msisdn_len;
    // char msisdn_bcd[OGS_MAX_MSISDN_BCD_LEN+1];

    // /* IMEI */
    // uint8_t imeisv[OGS_MAX_IMEISV_LEN];
    // int imeisv_len;
    // char  imeisv_bcd[OGS_MAX_IMEISV_BCD_LEN+1];

    // ogs_list_t sess_list
    OpenAPI_list_t *sess_list

);
void OpenAPI_smf_ue_free(OpenAPI_smf_ue_t *smf_ue);
OpenAPI_smf_ue_t *OpenAPI_smf_ue_parseFromJSON(cJSON *smf_ueJSON);
cJSON *OpenAPI_smf_ue_convertToJSON(OpenAPI_smf_ue_t *smf_ue);
OpenAPI_smf_ue_t *OpenAPI_smf_ue_copy(OpenAPI_smf_ue_t *dst, OpenAPI_smf_ue_t *src);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_smf_ue_H_ */

