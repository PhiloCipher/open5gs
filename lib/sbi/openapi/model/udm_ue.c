
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "udm_ue.h"

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
)
{
    OpenAPI_udm_ue_t *udm_ue_local_var = ogs_malloc(sizeof(OpenAPI_udm_ue_t));
    ogs_assert(udm_ue_local_var);

    // udm_ue_local_var->sbi = sbi;
    // udm_ue_local_var->sm = sm;
    // udm_ue_local_var->auth_event = auth_event;
    udm_ue_local_var->ctx_id = ctx_id;
    udm_ue_local_var->suci = suci;
    udm_ue_local_var->supi = supi;
    udm_ue_local_var->serving_network_name = serving_network_name;
    udm_ue_local_var->ausf_instance_id = ausf_instance_id;
    udm_ue_local_var->amf_instance_id = amf_instance_id;
    udm_ue_local_var->dereg_callback_uri = dereg_callback_uri;
    udm_ue_local_var->data_change_callback_uri = data_change_callback_uri;
    // udm_ue_local_var->k = k;
    if(opc){
        int i;
        for (i = 0; i < OGS_KEY_LEN; i++)
        {
        udm_ue_local_var->opc[i] = opc[i];
        }
    }
    
    // udm_ue_local_var->amf = amf;
    // udm_ue_local_var->rand = rand;
    // udm_ue_local_var->sqn = sqn;
    // udm_ue_local_var->guami = guami;
    // udm_ue_local_var->auth_type = auth_type;
    // udm_ue_local_var->rat_type = rat_type;

    return udm_ue_local_var;
}

void OpenAPI_udm_ue_free(OpenAPI_udm_ue_t *udm_ue)
{
    OpenAPI_lnode_t *node = NULL;

    if (NULL == udm_ue) {
        return;
    }
    // if (udm_ue->nf_instance_id) {
    //     ogs_free(udm_ue->nf_instance_id);
    //     udm_ue->nf_instance_id = NULL;
    // }
    // if (udm_ue->time_stamp) {
    //     ogs_free(udm_ue->time_stamp);
    //     udm_ue->time_stamp = NULL;
    // }
    // if (udm_ue->serving_network_name) {
    //     ogs_free(udm_ue->serving_network_name);
    //     udm_ue->serving_network_name = NULL;
    // }
    // if (udm_ue->nf_set_id) {
    //     ogs_free(udm_ue->nf_set_id);
    //     udm_ue->nf_set_id = NULL;
    // }
    // if (udm_ue->reset_ids) {
    //     OpenAPI_list_for_each(udm_ue->reset_ids, node) {
    //         ogs_free(node->data);
    //     }
    //     OpenAPI_list_free(udm_ue->reset_ids);
    //     udm_ue->reset_ids = NULL;
    // }
    ogs_free(udm_ue);
}

cJSON *OpenAPI_udm_ue_convertToJSON(OpenAPI_udm_ue_t *udm_ue)
{
    cJSON *item = NULL;
    OpenAPI_lnode_t *node = NULL;

    if (udm_ue == NULL) {
        ogs_error("OpenAPI_udm_ue_convertToJSON() failed [AuthEvent]");
        return NULL;
    }

    item = cJSON_CreateObject();

    if (udm_ue->ctx_id) {
	if (cJSON_AddStringToObject(item, "ctx_id", udm_ue->ctx_id) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [ctx_id]");
	    goto end;
	}
    }

    if (udm_ue->suci) {
	if (cJSON_AddStringToObject(item, "suci", udm_ue->suci) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [suci]");
	    goto end;
	}
    }

    if (udm_ue->supi) {
	if (cJSON_AddStringToObject(item, "supi", udm_ue->supi) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [supi]");
	    goto end;
	}
    }

    if (udm_ue->serving_network_name) {
	if (cJSON_AddStringToObject(item, "serving_network_name", udm_ue->serving_network_name) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [serving_network_name]");
	    goto end;
	}
    }

    if (udm_ue->ausf_instance_id) {
	if (cJSON_AddStringToObject(item, "ausf_instance_id", udm_ue->ausf_instance_id) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [ausf_instance_id]");
	    goto end;
	}
    }

    if (udm_ue->amf_instance_id) {
	if (cJSON_AddStringToObject(item, "amf_instance_id", udm_ue->amf_instance_id) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [amf_instance_id]");
	    goto end;
	}
    }

    if (udm_ue->dereg_callback_uri) {
	if (cJSON_AddStringToObject(item, "dereg_callback_uri", udm_ue->dereg_callback_uri) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [dereg_callback_uri]");
	    goto end;
	}
    }

    if (udm_ue->data_change_callback_uri) {
	if (cJSON_AddStringToObject(item, "data_change_callback_uri", udm_ue->data_change_callback_uri) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [data_change_callback_uri]");
	    goto end;
	}
    }

    if (udm_ue->opc) {
    char opc_string[2*OGS_RAND_LEN];
    ogs_hex_to_ascii(udm_ue->opc, sizeof(udm_ue->opc),
                    opc_string, sizeof(opc_string));
	if (cJSON_AddStringToObject(item, "opc", opc_string) == NULL) {
	    ogs_error("OpenAPI_udm_ue_convertToJSON() failed [opc]");
	    goto end;
	}
    }
    

    // if (!udm_ue->nf_instance_id) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [nf_instance_id]");
    //     return NULL;
    // }
    // if (cJSON_AddStringToObject(item, "nfInstanceId", udm_ue->nf_instance_id) == NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [nf_instance_id]");
    //     goto end;
    // }

    // if (cJSON_AddBoolToObject(item, "success", udm_ue->success) == NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [success]");
    //     goto end;
    // }

    // if (!udm_ue->time_stamp) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [time_stamp]");
    //     return NULL;
    // }
    // if (cJSON_AddStringToObject(item, "timeStamp", udm_ue->time_stamp) == NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [time_stamp]");
    //     goto end;
    // }

    // if (udm_ue->auth_type == OpenAPI_auth_type_NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [auth_type]");
    //     return NULL;
    // }
    // if (cJSON_AddStringToObject(item, "authType", OpenAPI_auth_type_ToString(udm_ue->auth_type)) == NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [auth_type]");
    //     goto end;
    // }

    // if (!udm_ue->serving_network_name) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [serving_network_name]");
    //     return NULL;
    // }
    // if (cJSON_AddStringToObject(item, "servingNetworkName", udm_ue->serving_network_name) == NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [serving_network_name]");
    //     goto end;
    // }

    // if (udm_ue->is_auth_removal_ind) {
    // if (cJSON_AddBoolToObject(item, "authRemovalInd", udm_ue->auth_removal_ind) == NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [auth_removal_ind]");
    //     goto end;
    // }
    // }

    // if (udm_ue->nf_set_id) {
    // if (cJSON_AddStringToObject(item, "nfSetId", udm_ue->nf_set_id) == NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [nf_set_id]");
    //     goto end;
    // }
    // }

    // if (udm_ue->reset_ids) {
    // cJSON *reset_idsList = cJSON_AddArrayToObject(item, "resetIds");
    // if (reset_idsList == NULL) {
    //     ogs_error("OpenAPI_udm_ue_convertToJSON() failed [reset_ids]");
    //     goto end;
    // }
    // OpenAPI_list_for_each(udm_ue->reset_ids, node) {
    //     if (cJSON_AddStringToObject(reset_idsList, "", (char*)node->data) == NULL) {
    //         ogs_error("OpenAPI_udm_ue_convertToJSON() failed [reset_ids]");
    //         goto end;
    //     }
    // }
    // }

end:
    return item;
}

OpenAPI_udm_ue_t *OpenAPI_udm_ue_parseFromJSON(cJSON *udm_ueJSON)
{
    OpenAPI_udm_ue_t *udm_ue_local_var = NULL;
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
    cJSON *ausf_instance_id = NULL;
    cJSON *amf_instance_id = NULL;
    cJSON *dereg_callback_uri = NULL;
    cJSON *data_change_callback_uri = NULL;
    cJSON *opc = NULL;
    uint8_t opcVariable[OGS_KEY_LEN];
    

    ctx_id = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "ctx_id");
    if (ctx_id) {
    if (!cJSON_IsString(ctx_id) && !cJSON_IsNull(ctx_id)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [ctx_id]");
	goto end;
    }}

    suci = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "suci");
    if (suci) {
    if (!cJSON_IsString(suci) && !cJSON_IsNull(suci)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [suci]");
	goto end;
    }}

    supi = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "supi");
    if (supi) {
    if (!cJSON_IsString(supi) && !cJSON_IsNull(supi)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [supi]");
	goto end;
    }}

    serving_network_name = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "serving_network_name");
    if (serving_network_name) {
    if (!cJSON_IsString(serving_network_name) && !cJSON_IsNull(serving_network_name)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [serving_network_name]");
	goto end;
    }}

    ausf_instance_id = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "ausf_instance_id");
    if (ausf_instance_id) {
    if (!cJSON_IsString(ausf_instance_id) && !cJSON_IsNull(ausf_instance_id)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [ausf_instance_id]");
	goto end;
    }}

    amf_instance_id = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "amf_instance_id");
    if (amf_instance_id) {
    if (!cJSON_IsString(amf_instance_id) && !cJSON_IsNull(amf_instance_id)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [amf_instance_id]");
	goto end;
    }}

    dereg_callback_uri = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "dereg_callback_uri");
    if (dereg_callback_uri) {
    if (!cJSON_IsString(dereg_callback_uri) && !cJSON_IsNull(dereg_callback_uri)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [dereg_callback_uri]");
	goto end;
    }}

    data_change_callback_uri = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "data_change_callback_uri");
    if (data_change_callback_uri) {
    if (!cJSON_IsString(data_change_callback_uri) && !cJSON_IsNull(data_change_callback_uri)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [data_change_callback_uri]");
	goto end;
    }}

    opc = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "opc");
    if (opc) {
    if (!cJSON_IsString(opc) && !cJSON_IsNull(opc)) {
	ogs_error("OpenAPI_udm_ue_parseFromJSON failed [opc]");
	goto end;
    }
    ogs_ascii_to_hex(opc->valuestring,strlen(opc->valuestring),
                    opcVariable, sizeof(opcVariable));
    }


//     nf_instance_id = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "nfInstanceId");
//     if (!nf_instance_id) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [nf_instance_id]");
//         goto end;
//     }
//     if (!cJSON_IsString(nf_instance_id)) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [nf_instance_id]");
//         goto end;
//     }

//     success = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "success");
//     if (!success) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [success]");
//         goto end;
//     }
//     if (!cJSON_IsBool(success)) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [success]");
//         goto end;
//     }

//     time_stamp = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "timeStamp");
//     if (!time_stamp) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [time_stamp]");
//         goto end;
//     }
//     if (!cJSON_IsString(time_stamp) && !cJSON_IsNull(time_stamp)) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [time_stamp]");
//         goto end;
//     }

//     auth_type = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "authType");
//     if (!auth_type) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [auth_type]");
//         goto end;
//     }
//     if (!cJSON_IsString(auth_type)) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [auth_type]");
//         goto end;
//     }
//     auth_typeVariable = OpenAPI_auth_type_FromString(auth_type->valuestring);

//     serving_network_name = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "servingNetworkName");
//     if (!serving_network_name) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }
//     if (!cJSON_IsString(serving_network_name)) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }

//     auth_removal_ind = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "authRemovalInd");
//     if (auth_removal_ind) {
//     if (!cJSON_IsBool(auth_removal_ind)) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [auth_removal_ind]");
//         goto end;
//     }
//     }

//     nf_set_id = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "nfSetId");
//     if (nf_set_id) {
//     if (!cJSON_IsString(nf_set_id) && !cJSON_IsNull(nf_set_id)) {
//         ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [nf_set_id]");
//         goto end;
//     }
//     }

//     reset_ids = cJSON_GetObjectItemCaseSensitive(udm_ueJSON, "resetIds");
//     if (reset_ids) {
//         cJSON *reset_ids_local = NULL;
//         if (!cJSON_IsArray(reset_ids)) {
//             ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [reset_ids]");
//             goto end;
//         }

//         reset_idsList = OpenAPI_list_create();

//         cJSON_ArrayForEach(reset_ids_local, reset_ids) {
//             double *localDouble = NULL;
//             int *localInt = NULL;
//             if (!cJSON_IsString(reset_ids_local)) {
//                 ogs_error("OpenAPI_udm_ue_parseFromJSON() failed [reset_ids]");
//                 goto end;
//             }
//             OpenAPI_list_add(reset_idsList, ogs_strdup(reset_ids_local->valuestring));
//         }
//     }
    
    udm_ue_local_var = OpenAPI_udm_ue_create (
        ctx_id && !cJSON_IsNull(ctx_id) ? ogs_strdup(ctx_id->valuestring) : NULL,
        suci && !cJSON_IsNull(suci) ? ogs_strdup(suci->valuestring) : NULL,
        supi && !cJSON_IsNull(supi) ? ogs_strdup(supi->valuestring) : NULL,
        serving_network_name && !cJSON_IsNull(serving_network_name) ? ogs_strdup(serving_network_name->valuestring) : NULL,
        ausf_instance_id && !cJSON_IsNull(ausf_instance_id) ? ogs_strdup(ausf_instance_id->valuestring) : NULL,
        amf_instance_id && !cJSON_IsNull(amf_instance_id) ? ogs_strdup(amf_instance_id->valuestring) : NULL,
        dereg_callback_uri && !cJSON_IsNull(dereg_callback_uri) ? ogs_strdup(dereg_callback_uri->valuestring) : NULL,
        data_change_callback_uri && !cJSON_IsNull(data_change_callback_uri) ? ogs_strdup(data_change_callback_uri->valuestring) : NULL,
        opc ? opcVariable : NULL
            
//         success->valueint,
//         ogs_strdup(time_stamp->valuestring),
//         auth_typeVariable,
//         ogs_strdup(serving_network_name->valuestring),
//         auth_removal_ind ? true : false,
//         auth_removal_ind ? auth_removal_ind->valueint : 0,
//         nf_set_id && !cJSON_IsNull(nf_set_id) ? ogs_strdup(nf_set_id->valuestring) : NULL,
//         reset_ids ? reset_idsList : NULL
    );

    return udm_ue_local_var;
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

OpenAPI_udm_ue_t *OpenAPI_udm_ue_copy(OpenAPI_udm_ue_t *dst, OpenAPI_udm_ue_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);
    item = OpenAPI_udm_ue_convertToJSON(src);
    if (!item) {
        ogs_error("OpenAPI_udm_ue_convertToJSON() failed");
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

    OpenAPI_udm_ue_free(dst);
    dst = OpenAPI_udm_ue_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
}

