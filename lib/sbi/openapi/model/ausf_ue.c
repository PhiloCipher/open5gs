
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ausf_ue.h"

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

)
{
    OpenAPI_ausf_ue_t *ausf_ue_local_var = ogs_malloc(sizeof(OpenAPI_ausf_ue_t));
    ogs_assert(ausf_ue_local_var);

    // ausf_ue_local_var->sbi = sbi;
    // ausf_ue_local_var->sm = sm;

    ausf_ue_local_var->ctx_id = ctx_id;
    ausf_ue_local_var->suci = suci;
    ausf_ue_local_var->supi = supi;
    ausf_ue_local_var->serving_network_name = serving_network_name;
    ausf_ue_local_var->auth_type = auth_type;
    ausf_ue_local_var->auth_events_url = auth_events_url;
    ausf_ue_local_var->auth_result = auth_result;

    return ausf_ue_local_var;
}

void OpenAPI_ausf_ue_free(OpenAPI_ausf_ue_t *ausf_ue)
{
    OpenAPI_lnode_t *node = NULL;

    if (NULL == ausf_ue) {
        return;
    }
    // if (ausf_ue->nf_instance_id) {
    //     ogs_free(ausf_ue->nf_instance_id);
    //     ausf_ue->nf_instance_id = NULL;
    // }
    // if (ausf_ue->time_stamp) {
    //     ogs_free(ausf_ue->time_stamp);
    //     ausf_ue->time_stamp = NULL;
    // }
    // if (ausf_ue->serving_network_name) {
    //     ogs_free(ausf_ue->serving_network_name);
    //     ausf_ue->serving_network_name = NULL;
    // }
    // if (ausf_ue->nf_set_id) {
    //     ogs_free(ausf_ue->nf_set_id);
    //     ausf_ue->nf_set_id = NULL;
    // }
    // if (ausf_ue->reset_ids) {
    //     OpenAPI_list_for_each(ausf_ue->reset_ids, node) {
    //         ogs_free(node->data);
    //     }
    //     OpenAPI_list_free(ausf_ue->reset_ids);
    //     ausf_ue->reset_ids = NULL;
    // }
    ogs_free(ausf_ue);
}

cJSON *OpenAPI_ausf_ue_convertToJSON(OpenAPI_ausf_ue_t *ausf_ue)
{
    cJSON *item = NULL;
    OpenAPI_lnode_t *node = NULL;

    if (ausf_ue == NULL) {
        ogs_error("OpenAPI_ausf_ue_convertToJSON() failed [AuthEvent]");
        return NULL;
    }

    item = cJSON_CreateObject();

    if (ausf_ue->ctx_id) {
	if (cJSON_AddStringToObject(item, "ctx_id", ausf_ue->ctx_id) == NULL) {
	    ogs_error("OpenAPI_ausf_ue_convertToJSON() failed [ctx_id]");
	    goto end;
	}
    }

    if (ausf_ue->suci) {
	if (cJSON_AddStringToObject(item, "suci", ausf_ue->suci) == NULL) {
	    ogs_error("OpenAPI_ausf_ue_convertToJSON() failed [suci]");
	    goto end;
	}
    }

    if (ausf_ue->supi) {
	if (cJSON_AddStringToObject(item, "supi", ausf_ue->supi) == NULL) {
	    ogs_error("OpenAPI_ausf_ue_convertToJSON() failed [supi]");
	    goto end;
	}
    }

    if (ausf_ue->serving_network_name) {
	if (cJSON_AddStringToObject(item, "serving_network_name", ausf_ue->serving_network_name) == NULL) {
	    ogs_error("OpenAPI_ausf_ue_convertToJSON() failed [serving_network_name]");
	    goto end;
	}
    }

    if (ausf_ue->auth_type != OpenAPI_auth_type_NULL) {
	if (cJSON_AddStringToObject(item, "auth_type", OpenAPI_auth_type_ToString(ausf_ue->auth_type)) == NULL) {
	    ogs_error("OpenAPI_ausf_ue_convertToJSON() failed [auth_type]");
	    goto end;
	}
    }

    if (ausf_ue->auth_events_url) {
	if (cJSON_AddStringToObject(item, "auth_events_url", ausf_ue->auth_events_url) == NULL) {
	    ogs_error("OpenAPI_ausf_ue_convertToJSON() failed [auth_events_url]");
	    goto end;
	}
    }

    if (ausf_ue->auth_result != OpenAPI_auth_result_NULL) {
	if (cJSON_AddStringToObject(item, "auth_result", OpenAPI_auth_result_ToString(ausf_ue->auth_result)) == NULL) {
	    ogs_error("OpenAPI_ausf_ue_convertToJSON() failed [auth_result]");
	    goto end;
	}
    }


end:
    return item;
}

OpenAPI_ausf_ue_t *OpenAPI_ausf_ue_parseFromJSON(cJSON *ausf_ueJSON)
{
    OpenAPI_ausf_ue_t *ausf_ue_local_var = NULL;
//     OpenAPI_lnode_t *node = NULL;
//     cJSON *nf_instance_id = NULL;
//     cJSON *success = NULL;
//     cJSON *time_stamp = NULL;
//     cJSON *auth_type = NULL;
//     OpenAPI_auth_type_e auth_typeVariable = 0;
//     cJSON *serving_network_name = NULL;
//     cJSON *auth_removal_ind = NULL;
//     cJSON *nf_set_id = NULL;
//     cJSON *reset_ids = NULL;
//     OpenAPI_list_t *reset_idsList = NULL;
    cJSON *ctx_id = NULL;
    cJSON *suci = NULL;
    cJSON *supi = NULL;
    cJSON *serving_network_name = NULL;
    cJSON *auth_type = NULL;
    OpenAPI_auth_type_e auth_typeVariable = 0;
    cJSON *auth_events_url = NULL;
    cJSON *auth_result = NULL;
    OpenAPI_auth_result_e auth_resultVariable = 0;

    ctx_id = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "ctx_id");
    if (ctx_id) {
    if (!cJSON_IsString(ctx_id) && !cJSON_IsNull(ctx_id)) {
	ogs_error("OpenAPI_ausf_ue_parseFromJSON failed [ctx_id]");
	goto end;
    }}

    suci = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "suci");
    if (suci) {
    if (!cJSON_IsString(suci) && !cJSON_IsNull(suci)) {
	ogs_error("OpenAPI_ausf_ue_parseFromJSON failed [suci]");
	goto end;
    }}

    supi = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "supi");
    if (supi) {
    if (!cJSON_IsString(supi) && !cJSON_IsNull(supi)) {
	ogs_error("OpenAPI_ausf_ue_parseFromJSON failed [supi]");
	goto end;
    }}

    serving_network_name = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "serving_network_name");
    if (serving_network_name) {
    if (!cJSON_IsString(serving_network_name) && !cJSON_IsNull(serving_network_name)) {
	ogs_error("OpenAPI_ausf_ue_parseFromJSON failed [serving_network_name]");
	goto end;
    }}

    auth_type = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "auth_type");
    if (auth_type) {
    if (!cJSON_IsString(auth_type)) {
        ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [auth_type]");
        goto end;
    }
    auth_typeVariable = OpenAPI_auth_type_FromString(auth_type->valuestring);
    }

    auth_events_url = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "auth_events_url");
    if (auth_events_url) {
    if (!cJSON_IsString(auth_events_url) && !cJSON_IsNull(auth_events_url)) {
	ogs_error("OpenAPI_ausf_ue_parseFromJSON failed [auth_events_url]");
	goto end;
    }}

    auth_result = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "auth_result");
    if (auth_result) {
    if (!cJSON_IsString(auth_result)) {
        ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [auth_result]");
        goto end;
    }
    auth_resultVariable = OpenAPI_auth_result_FromString(auth_result->valuestring);
    }
//     nf_instance_id = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "nfInstanceId");
//     if (!nf_instance_id) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [nf_instance_id]");
//         goto end;
//     }
//     if (!cJSON_IsString(nf_instance_id)) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [nf_instance_id]");
//         goto end;
//     }

//     success = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "success");
//     if (!success) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [success]");
//         goto end;
//     }
//     if (!cJSON_IsBool(success)) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [success]");
//         goto end;
//     }

//     time_stamp = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "timeStamp");
//     if (!time_stamp) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [time_stamp]");
//         goto end;
//     }
//     if (!cJSON_IsString(time_stamp) && !cJSON_IsNull(time_stamp)) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [time_stamp]");
//         goto end;
//     }

//     auth_type = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "authType");
//     if (!auth_type) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [auth_type]");
//         goto end;
//     }
//     if (!cJSON_IsString(auth_type)) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [auth_type]");
//         goto end;
//     }
//     auth_typeVariable = OpenAPI_auth_type_FromString(auth_type->valuestring);

//     serving_network_name = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "servingNetworkName");
//     if (!serving_network_name) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }
//     if (!cJSON_IsString(serving_network_name)) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }

//     auth_removal_ind = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "authRemovalInd");
//     if (auth_removal_ind) {
//     if (!cJSON_IsBool(auth_removal_ind)) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [auth_removal_ind]");
//         goto end;
//     }
//     }

//     nf_set_id = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "nfSetId");
//     if (nf_set_id) {
//     if (!cJSON_IsString(nf_set_id) && !cJSON_IsNull(nf_set_id)) {
//         ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [nf_set_id]");
//         goto end;
//     }
//     }

//     reset_ids = cJSON_GetObjectItemCaseSensitive(ausf_ueJSON, "resetIds");
//     if (reset_ids) {
//         cJSON *reset_ids_local = NULL;
//         if (!cJSON_IsArray(reset_ids)) {
//             ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [reset_ids]");
//             goto end;
//         }

//         reset_idsList = OpenAPI_list_create();

//         cJSON_ArrayForEach(reset_ids_local, reset_ids) {
//             double *localDouble = NULL;
//             int *localInt = NULL;
//             if (!cJSON_IsString(reset_ids_local)) {
//                 ogs_error("OpenAPI_ausf_ue_parseFromJSON() failed [reset_ids]");
//                 goto end;
//             }
//             OpenAPI_list_add(reset_idsList, ogs_strdup(reset_ids_local->valuestring));
//         }
//     }
    
    ausf_ue_local_var = OpenAPI_ausf_ue_create (
        ctx_id && !cJSON_IsNull(ctx_id) ? ogs_strdup(ctx_id->valuestring) : NULL,
        suci && !cJSON_IsNull(suci) ? ogs_strdup(suci->valuestring) : NULL,
        supi && !cJSON_IsNull(supi) ? ogs_strdup(supi->valuestring) : NULL,
        serving_network_name && !cJSON_IsNull(serving_network_name) ? ogs_strdup(serving_network_name->valuestring) : NULL,
        auth_type ? auth_typeVariable : 0,
        auth_events_url && !cJSON_IsNull(auth_events_url) ? ogs_strdup(auth_events_url->valuestring) : NULL,
        auth_result ? auth_resultVariable : 0
            
//         success->valueint,
//         ogs_strdup(time_stamp->valuestring),
//         auth_typeVariable,
//         ogs_strdup(serving_network_name->valuestring),
//         auth_removal_ind ? true : false,
//         auth_removal_ind ? auth_removal_ind->valueint : 0,
//         nf_set_id && !cJSON_IsNull(nf_set_id) ? ogs_strdup(nf_set_id->valuestring) : NULL,
//         reset_ids ? reset_idsList : NULL
    );

    return ausf_ue_local_var;
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

OpenAPI_ausf_ue_t *OpenAPI_ausf_ue_copy(OpenAPI_ausf_ue_t *dst, OpenAPI_ausf_ue_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);
    item = OpenAPI_ausf_ue_convertToJSON(src);
    if (!item) {
        ogs_error("OpenAPI_ausf_ue_convertToJSON() failed");
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

    OpenAPI_ausf_ue_free(dst);
    dst = OpenAPI_ausf_ue_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
}

