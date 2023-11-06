
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "smf_sess.h"

OpenAPI_smf_sess_t *OpenAPI_smf_sess_create(
    ogs_session_t session,
    uint8_t ue_session_type,
    uint8_t ue_ssc_mode,

    char *ipv4,
    char *ipv6
)
{
    OpenAPI_smf_sess_t *smf_sess_local_var = ogs_malloc(sizeof(OpenAPI_smf_sess_t));
    ogs_assert(smf_sess_local_var);

    smf_sess_local_var->session = session;
    smf_sess_local_var->ue_session_type = ue_session_type;
    smf_sess_local_var->ue_ssc_mode = ue_ssc_mode;
    smf_sess_local_var->ipv4 = ipv4;
    smf_sess_local_var->ipv6 = ipv6;


    return smf_sess_local_var;
}

void OpenAPI_smf_sess_free(OpenAPI_smf_sess_t *smf_sess)
{
    OpenAPI_lnode_t *node = NULL;

    if (NULL == smf_sess) {
        return;
    }

    ogs_free(smf_sess);
}

cJSON *OpenAPI_smf_sess_convertToJSON(OpenAPI_smf_sess_t *smf_sess)
{
    cJSON *item = NULL;
    OpenAPI_lnode_t *node = NULL;

    if (smf_sess == NULL) {
        ogs_error("OpenAPI_smf_sess_convertToJSON() failed [smf_sess]");
        return NULL;
    }

    item = cJSON_CreateObject();

    if (&smf_sess->session) {
	if (cJSON_AddStringToObject(item, "session.name", smf_sess->session.name) == NULL) {
	    ogs_error("OpenAPI_smf_sess_convertToJSON() failed [session.name]");
	    goto end;
	}
    }

    if (smf_sess->ue_session_type) {
	if (cJSON_AddNumberToObject(item, "ue_session_type", smf_sess->ue_session_type) == NULL) {
	    ogs_error("OpenAPI_smf_sess_convertToJSON() failed [ue_session_type]");
	    goto end;
	}
    }

    if (smf_sess->ue_ssc_mode) {
	if (cJSON_AddNumberToObject(item, "ue_ssc_mode", smf_sess->ue_ssc_mode) == NULL) {
	    ogs_error("OpenAPI_smf_sess_convertToJSON() failed [ue_ssc_mode]");
	    goto end;
	}
    }

    if (&smf_sess->ipv4) {
	if (cJSON_AddStringToObject(item, "ipv4", smf_sess->ipv4) == NULL) {
	    ogs_error("OpenAPI_smf_sess_convertToJSON() failed [ipv4]");
	    goto end;
	}
    }

    if (&smf_sess->ipv6) {
	if (cJSON_AddStringToObject(item, "ipv6", smf_sess->ipv6) == NULL) {
	    ogs_error("OpenAPI_smf_sess_convertToJSON() failed [ipv6]");
	    goto end;
	}
    }
    // if (&smf_sess->ipv4) {
    // char buf1[OGS_ADDRSTRLEN];
    // OGS_INET_NTOP(&smf_sess->ipv4->addr, buf1);
	// if (cJSON_AddStringToObject(item, "ipv4", buf1) == NULL) {
	//     ogs_error("OpenAPI_smf_sess_convertToJSON() failed [ipv4]");
	//     goto end;
	// }
    // }

    // if (&smf_sess->ipv6) {
    // char buf2[OGS_ADDRSTRLEN];
    // OGS_INET_NTOP(&smf_sess->ipv6->addr, buf2);
	// if (cJSON_AddStringToObject(item, "ipv6", buf2) == NULL) {
	//     ogs_error("OpenAPI_smf_sess_convertToJSON() failed [ipv6]");
	//     goto end;
	// }
    // }

end:
    return item;
}

OpenAPI_smf_sess_t *OpenAPI_smf_sess_parseFromJSON(cJSON *smf_sessJSON)
{
    OpenAPI_smf_sess_t *smf_sess_local_var = NULL;

    cJSON *supi = NULL;

    // supi = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "supi");
    // if (supi) {
    // if (!cJSON_IsString(supi) && !cJSON_IsNull(supi)) {
	// ogs_error("OpenAPI_smf_sess_parseFromJSON failed [supi]");
	// goto end;
    // }}


//     nf_instance_id = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "nfInstanceId");
//     if (!nf_instance_id) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [nf_instance_id]");
//         goto end;
//     }
//     if (!cJSON_IsString(nf_instance_id)) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [nf_instance_id]");
//         goto end;
//     }

//     success = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "success");
//     if (!success) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [success]");
//         goto end;
//     }
//     if (!cJSON_IsBool(success)) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [success]");
//         goto end;
//     }

//     time_stamp = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "timeStamp");
//     if (!time_stamp) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [time_stamp]");
//         goto end;
//     }
//     if (!cJSON_IsString(time_stamp) && !cJSON_IsNull(time_stamp)) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [time_stamp]");
//         goto end;
//     }

//     auth_type = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "authType");
//     if (!auth_type) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [auth_type]");
//         goto end;
//     }
//     if (!cJSON_IsString(auth_type)) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [auth_type]");
//         goto end;
//     }
//     auth_typeVariable = OpenAPI_auth_type_FromString(auth_type->valuestring);

//     serving_network_name = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "servingNetworkName");
//     if (!serving_network_name) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }
//     if (!cJSON_IsString(serving_network_name)) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }

//     auth_removal_ind = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "authRemovalInd");
//     if (auth_removal_ind) {
//     if (!cJSON_IsBool(auth_removal_ind)) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [auth_removal_ind]");
//         goto end;
//     }
//     }

//     nf_set_id = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "nfSetId");
//     if (nf_set_id) {
//     if (!cJSON_IsString(nf_set_id) && !cJSON_IsNull(nf_set_id)) {
//         ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [nf_set_id]");
//         goto end;
//     }
//     }

//     reset_ids = cJSON_GetObjectItemCaseSensitive(smf_sessJSON, "resetIds");
//     if (reset_ids) {
//         cJSON *reset_ids_local = NULL;
//         if (!cJSON_IsArray(reset_ids)) {
//             ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [reset_ids]");
//             goto end;
//         }

//         reset_idsList = OpenAPI_list_create();

//         cJSON_ArrayForEach(reset_ids_local, reset_ids) {
//             double *localDouble = NULL;
//             int *localInt = NULL;
//             if (!cJSON_IsString(reset_ids_local)) {
//                 ogs_error("OpenAPI_smf_sess_parseFromJSON() failed [reset_ids]");
//                 goto end;
//             }
//             OpenAPI_list_add(reset_idsList, ogs_strdup(reset_ids_local->valuestring));
//         }
//     }
    
    // smf_sess_local_var = OpenAPI_smf_sess_create (
    //     supi && !cJSON_IsNull(supi) ? ogs_strdup(supi->valuestring) : NULL


    // );

    return smf_sess_local_var;
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

OpenAPI_smf_sess_t *OpenAPI_smf_sess_copy(OpenAPI_smf_sess_t *dst, OpenAPI_smf_sess_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);
    item = OpenAPI_smf_sess_convertToJSON(src);
    if (!item) {
        ogs_error("OpenAPI_smf_sess_convertToJSON() failed");
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

    OpenAPI_smf_sess_free(dst);
    dst = OpenAPI_smf_sess_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
}

