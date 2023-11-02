/*
 * ausf_ue.h
 *
 * 
 */

#ifndef _OpenAPI_ausf_ue_H_
#define _OpenAPI_ausf_ue_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "../../../crypt/ogs-crypt.h"
#include "auth_type.h"
#include "auth_result.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_ausf_ue_s OpenAPI_ausf_ue_t;
typedef struct OpenAPI_ausf_ue_s {
    // ogs_sbi_object_t sbi;
    //ogs_fsm_t sm;

    char *ctx_id;
    char *suci;
    char *supi;
    char *serving_network_name;

    OpenAPI_auth_type_e auth_type;
    char *auth_events_url;
    OpenAPI_auth_result_e auth_result;

    // uint8_t rand[OGS_RAND_LEN];
    // uint8_t xres_star[OGS_MAX_RES_LEN];
    // uint8_t hxres_star[OGS_MAX_RES_LEN];
    // uint8_t kausf[OGS_SHA256_DIGEST_SIZE];
    // uint8_t kseaf[OGS_SHA256_DIGEST_SIZE];
} OpenAPI_ausf_ue_t;

OpenAPI_ausf_ue_t *OpenAPI_ausf_ue_create(
    // ogs_sbi_object_t sbi;
    //ogs_fsm_t sm;

    char *ctx_id,
    char *suci,
    char *supi,
    char *serving_network_name,

    OpenAPI_auth_type_e auth_type,
    char *auth_events_url,
    OpenAPI_auth_result_e auth_result

    // uint8_t rand[OGS_RAND_LEN];
    // uint8_t xres_star[OGS_MAX_RES_LEN];
    // uint8_t hxres_star[OGS_MAX_RES_LEN];
    // uint8_t kausf[OGS_SHA256_DIGEST_SIZE];
    // uint8_t kseaf[OGS_SHA256_DIGEST_SIZE];

);
void OpenAPI_ausf_ue_free(OpenAPI_ausf_ue_t *ausf_ue);
OpenAPI_ausf_ue_t *OpenAPI_ausf_ue_parseFromJSON(cJSON *ausf_ueJSON);
cJSON *OpenAPI_ausf_ue_convertToJSON(OpenAPI_ausf_ue_t *ausf_ue);
OpenAPI_ausf_ue_t *OpenAPI_ausf_ue_copy(OpenAPI_ausf_ue_t *dst, OpenAPI_ausf_ue_t *src);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_ausf_ue_H_ */

