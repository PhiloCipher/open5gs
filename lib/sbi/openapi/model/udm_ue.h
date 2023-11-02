/*
 * udm_ue.h
 *
 * 
 */

#ifndef _OpenAPI_udm_ue_H_
#define _OpenAPI_udm_ue_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "auth_event.h"
#include "../../../crypt/ogs-crypt.h"
#include "amf3_gpp_access_registration.h"
#include "rat_type.h"

// #include "../../ogs-sbi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_udm_ue_s OpenAPI_udm_ue_t;
typedef struct OpenAPI_udm_ue_s {
    // ogs_sbi_object_t sbi;
    ogs_fsm_t sm;

    OpenAPI_auth_event_t *auth_event;
    OpenAPI_amf3_gpp_access_registration_t *amf_3gpp_access_registration;

    char *ctx_id;
    char *suci;
    char *supi;
    char *serving_network_name;

    char *ausf_instance_id;
    char *amf_instance_id;

    char *dereg_callback_uri;
    char *data_change_callback_uri;

    uint8_t k[OGS_KEY_LEN];
    uint8_t opc[OGS_KEY_LEN];
    uint8_t amf[OGS_AMF_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t sqn[OGS_SQN_LEN];

    ogs_guami_t guami;

    OpenAPI_auth_type_e auth_type;
    OpenAPI_rat_type_e rat_type;
} OpenAPI_udm_ue_t;

OpenAPI_udm_ue_t *OpenAPI_udm_ue_create(
    // ogs_sbi_object_t sbi,
    // ogs_fsm_t sm,

    // OpenAPI_auth_event_t *auth_event,
    // OpenAPI_amf3_gpp_access_registration_t *amf_3gpp_access_registration,

    char *ctx_id,
    char *suci,
    char *supi,
    char *serving_network_name,

    char *ausf_instance_id,
    char *amf_instance_id,

    char *dereg_callback_uri,
    char *data_change_callback_uri,

    // uint8_t k[OGS_KEY_LEN],
    uint8_t opc[OGS_KEY_LEN]
    // uint8_t amf[OGS_AMF_LEN],
    // uint8_t rand[OGS_RAND_LEN],
    // uint8_t sqn[OGS_SQN_LEN],

    // ogs_guami_t guami,

    // OpenAPI_auth_type_e auth_type,
    // OpenAPI_rat_type_e rat_type

);
void OpenAPI_udm_ue_free(OpenAPI_udm_ue_t *udm_ue);
OpenAPI_udm_ue_t *OpenAPI_udm_ue_parseFromJSON(cJSON *udm_ueJSON);
cJSON *OpenAPI_udm_ue_convertToJSON(OpenAPI_udm_ue_t *udm_ue);
OpenAPI_udm_ue_t *OpenAPI_udm_ue_copy(OpenAPI_udm_ue_t *dst, OpenAPI_udm_ue_t *src);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_udm_ue_H_ */

