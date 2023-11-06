
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "smf_ue.h"

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
)
{
    OpenAPI_smf_ue_t *smf_ue_local_var = ogs_malloc(sizeof(OpenAPI_smf_ue_t));
    ogs_assert(smf_ue_local_var);

    smf_ue_local_var->supi = supi;
    smf_ue_local_var->sess_list = sess_list;


    return smf_ue_local_var;
}

void OpenAPI_smf_ue_free(OpenAPI_smf_ue_t *smf_ue)
{
    OpenAPI_lnode_t *node = NULL;

    if (NULL == smf_ue) {
        return;
    }

    ogs_free(smf_ue);
}

cJSON *OpenAPI_smf_ue_convertToJSON(OpenAPI_smf_ue_t *smf_ue)
{
    cJSON *item = NULL;
    OpenAPI_lnode_t *node = NULL;

    if (smf_ue == NULL) {
        ogs_error("OpenAPI_smf_ue_convertToJSON() failed [smf_ue]");
        return NULL;
    }

    item = cJSON_CreateObject();

    if (smf_ue->supi) {
	if (cJSON_AddStringToObject(item, "supi", smf_ue->supi) == NULL) {
	    ogs_error("OpenAPI_smf_ue_convertToJSON() failed [supi]");
	    goto end;
	}
    }

    if (&smf_ue->sess_list) {
    cJSON *sess_listList = cJSON_AddArrayToObject(item, "{sess_list}");
    if (sess_listList == NULL) {
	ogs_error("OpenAPI_smf_ue_convertToJSON() failed [sess_list]");
	goto end;
    }
    OpenAPI_list_for_each(smf_ue->sess_list, node) {
    char buf1[OGS_ADDRSTRLEN];
    ogs_tmp("OPENIIP is %s", ((OpenAPI_smf_sess_t *)(node->data))->ipv4);
	cJSON *itemLocal = OpenAPI_smf_sess_convertToJSON(node->data);
	if (itemLocal == NULL) {
	    ogs_error("OpenAPI_smf_ue_convertToJSON() failed [sess_list]");
	    goto end;
	}
	cJSON_AddItemToArray(sess_listList, itemLocal);
    }
    }
end:
    return item;
}

OpenAPI_smf_ue_t *OpenAPI_smf_ue_parseFromJSON(cJSON *smf_ueJSON)
{
    OpenAPI_smf_ue_t *smf_ue_local_var = NULL;

    cJSON *supi = NULL;
    cJSON *sess_list = NULL;

    supi = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "supi");
    if (supi) {
    if (!cJSON_IsString(supi) && !cJSON_IsNull(supi)) {
	ogs_error("OpenAPI_smf_ue_parseFromJSON failed [supi]");
	goto end;
    }}


//     nf_instance_id = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "nfInstanceId");
//     if (!nf_instance_id) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [nf_instance_id]");
//         goto end;
//     }
//     if (!cJSON_IsString(nf_instance_id)) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [nf_instance_id]");
//         goto end;
//     }

//     success = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "success");
//     if (!success) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [success]");
//         goto end;
//     }
//     if (!cJSON_IsBool(success)) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [success]");
//         goto end;
//     }

//     time_stamp = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "timeStamp");
//     if (!time_stamp) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [time_stamp]");
//         goto end;
//     }
//     if (!cJSON_IsString(time_stamp) && !cJSON_IsNull(time_stamp)) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [time_stamp]");
//         goto end;
//     }

//     auth_type = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "authType");
//     if (!auth_type) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [auth_type]");
//         goto end;
//     }
//     if (!cJSON_IsString(auth_type)) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [auth_type]");
//         goto end;
//     }
//     auth_typeVariable = OpenAPI_auth_type_FromString(auth_type->valuestring);

//     serving_network_name = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "servingNetworkName");
//     if (!serving_network_name) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }
//     if (!cJSON_IsString(serving_network_name)) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }

//     auth_removal_ind = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "authRemovalInd");
//     if (auth_removal_ind) {
//     if (!cJSON_IsBool(auth_removal_ind)) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [auth_removal_ind]");
//         goto end;
//     }
//     }

//     nf_set_id = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "nfSetId");
//     if (nf_set_id) {
//     if (!cJSON_IsString(nf_set_id) && !cJSON_IsNull(nf_set_id)) {
//         ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [nf_set_id]");
//         goto end;
//     }
//     }

//     reset_ids = cJSON_GetObjectItemCaseSensitive(smf_ueJSON, "resetIds");
//     if (reset_ids) {
//         cJSON *reset_ids_local = NULL;
//         if (!cJSON_IsArray(reset_ids)) {
//             ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [reset_ids]");
//             goto end;
//         }

//         reset_idsList = OpenAPI_list_create();

//         cJSON_ArrayForEach(reset_ids_local, reset_ids) {
//             double *localDouble = NULL;
//             int *localInt = NULL;
//             if (!cJSON_IsString(reset_ids_local)) {
//                 ogs_error("OpenAPI_smf_ue_parseFromJSON() failed [reset_ids]");
//                 goto end;
//             }
//             OpenAPI_list_add(reset_idsList, ogs_strdup(reset_ids_local->valuestring));
//         }
//     }
    OpenAPI_list_t *a;
    smf_ue_local_var = OpenAPI_smf_ue_create (
        supi && !cJSON_IsNull(supi) ? ogs_strdup(supi->valuestring) : NULL,
        sess_list ? a : a

            
//         success->valueint,
//         ogs_strdup(time_stamp->valuestring),
//         auth_typeVariable,
//         ogs_strdup(serving_network_name->valuestring),
//         auth_removal_ind ? true : false,
//         auth_removal_ind ? auth_removal_ind->valueint : 0,
//         nf_set_id && !cJSON_IsNull(nf_set_id) ? ogs_strdup(nf_set_id->valuestring) : NULL,
//         reset_ids ? reset_idsList : NULL
    );

    return smf_ue_local_var;
end:
//     if (reset_idsList) {
//         OpenAPI_list_for_each(reset_idsList, node) {
//             ogs_free(node->data);
//         }
//         OpenAPI_list_free(reset_idsList);
//         reset_idsList = NULL;
//     }
    return NULL;
}

OpenAPI_smf_ue_t *OpenAPI_smf_ue_copy(OpenAPI_smf_ue_t *dst, OpenAPI_smf_ue_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);
    item = OpenAPI_smf_ue_convertToJSON(src);
    if (!item) {
        ogs_error("OpenAPI_smf_ue_convertToJSON() failed");
        return NULL;
    }

    content = cJSON_Print(item);
    cJSON_Delete(item);

    if (!content) {
        ogs_error("cJSON_Print() failed");
        return NULL;
    }

    item = cJSON_Parse(content);
    ogs_free(content);
    if (!item) {
        ogs_error("cJSON_Parse() failed");
        return NULL;
    }

    OpenAPI_smf_ue_free(dst);
    dst = OpenAPI_smf_ue_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
}

