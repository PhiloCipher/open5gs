
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "input_data.h"

OpenAPI_input_data_t *OpenAPI_input_data_create(
    OpenAPI_external_client_type_t external_client_type,
    char *supi,
    char *pei
)
{
    OpenAPI_input_data_t *input_data_local_var = ogs_malloc(sizeof(OpenAPI_input_data_t));
    ogs_assert(input_data_local_var);

    input_data_local_var->external_client_type = external_client_type;
    input_data_local_var->supi = supi;
    input_data_local_var->pei = pei;

    return input_data_local_var;
}

void OpenAPI_input_data_free(OpenAPI_input_data_t *input_data)
{
    OpenAPI_lnode_t *node = NULL;

    if (NULL == input_data) {
        return;
    }
    if (input_data->external_client_type) {
        ogs_free(input_data->external_client_type);
        input_data->external_client_type = NULL;
    }
    if (input_data->supi) {
        OpenAPI_pei_free(input_data->supi);
        input_data->supi = NULL;
    }
    if (input_data->pei) {
        OpenAPI_trace_data_free(input_data->pei);
        input_data->pei = NULL;
    }
    
    ogs_free(input_data);
}

cJSON *OpenAPI_input_data_convertToJSON(OpenAPI_input_data_t *input_data)
{
    cJSON *item = NULL;
    OpenAPI_lnode_t *node = NULL;

    if (input_data == NULL) {
        ogs_error("OpenAPI_input_data_convertToJSON() failed [AuthenticationInfo]");
        return NULL;
    }

//     item = cJSON_CreateObject();
//     if (!input_data->supi_or_suci) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [supi_or_suci]");
//         return NULL;
//     }
//     if (cJSON_AddStringToObject(item, "supiOrSuci", input_data->supi_or_suci) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [supi_or_suci]");
//         goto end;
//     }

//     if (!input_data->serving_network_name) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [serving_network_name]");
//         return NULL;
//     }
//     if (cJSON_AddStringToObject(item, "servingNetworkName", input_data->serving_network_name) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [serving_network_name]");
//         goto end;
//     }

//     if (input_data->resynchronization_info) {
//     cJSON *resynchronization_info_local_JSON = OpenAPI_resynchronization_info_convertToJSON(input_data->resynchronization_info);
//     if (resynchronization_info_local_JSON == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [resynchronization_info]");
//         goto end;
//     }
//     cJSON_AddItemToObject(item, "resynchronizationInfo", resynchronization_info_local_JSON);
//     if (item->child == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [resynchronization_info]");
//         goto end;
//     }
//     }

//     if (input_data->pei) {
//     if (cJSON_AddStringToObject(item, "pei", input_data->pei) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [pei]");
//         goto end;
//     }
//     }

//     if (input_data->trace_data) {
//     cJSON *trace_data_local_JSON = OpenAPI_trace_data_convertToJSON(input_data->trace_data);
//     if (trace_data_local_JSON == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [trace_data]");
//         goto end;
//     }
//     cJSON_AddItemToObject(item, "traceData", trace_data_local_JSON);
//     if (item->child == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [trace_data]");
//         goto end;
//     }
//     }

//     if (input_data->udm_group_id) {
//     if (cJSON_AddStringToObject(item, "udmGroupId", input_data->udm_group_id) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [udm_group_id]");
//         goto end;
//     }
//     }

//     if (input_data->routing_indicator) {
//     if (cJSON_AddStringToObject(item, "routingIndicator", input_data->routing_indicator) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [routing_indicator]");
//         goto end;
//     }
//     }

//     if (input_data->cell_cag_info) {
//     cJSON *cell_cag_infoList = cJSON_AddArrayToObject(item, "cellCagInfo");
//     if (cell_cag_infoList == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [cell_cag_info]");
//         goto end;
//     }
//     OpenAPI_list_for_each(input_data->cell_cag_info, node) {
//         if (cJSON_AddStringToObject(cell_cag_infoList, "", (char*)node->data) == NULL) {
//             ogs_error("OpenAPI_input_data_convertToJSON() failed [cell_cag_info]");
//             goto end;
//         }
//     }
//     }

//     if (input_data->is_n5gc_ind) {
//     if (cJSON_AddBoolToObject(item, "n5gcInd", input_data->n5gc_ind) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [n5gc_ind]");
//         goto end;
//     }
//     }

//     if (input_data->supported_features) {
//     if (cJSON_AddStringToObject(item, "supportedFeatures", input_data->supported_features) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [supported_features]");
//         goto end;
//     }
//     }

//     if (input_data->is_nswo_ind) {
//     if (cJSON_AddBoolToObject(item, "nswoInd", input_data->nswo_ind) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [nswo_ind]");
//         goto end;
//     }
//     }

//     if (input_data->is_disaster_roaming_ind) {
//     if (cJSON_AddBoolToObject(item, "disasterRoamingInd", input_data->disaster_roaming_ind) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [disaster_roaming_ind]");
//         goto end;
//     }
//     }

//     if (input_data->is_onboarding_ind) {
//     if (cJSON_AddBoolToObject(item, "onboardingInd", input_data->onboarding_ind) == NULL) {
//         ogs_error("OpenAPI_input_data_convertToJSON() failed [onboarding_ind]");
//         goto end;
//     }
//     }

// end:
    return item;
}

OpenAPI_input_data_t *OpenAPI_input_data_parseFromJSON(cJSON *input_dataJSON)
{
//     OpenAPI_input_data_t *input_data_local_var = NULL;
//     OpenAPI_lnode_t *node = NULL;
//     cJSON *supi_or_suci = NULL;
//     cJSON *serving_network_name = NULL;
//     cJSON *resynchronization_info = NULL;
//     OpenAPI_resynchronization_info_t *resynchronization_info_local_nonprim = NULL;
//     cJSON *pei = NULL;
//     cJSON *trace_data = NULL;
//     OpenAPI_trace_data_t *trace_data_local_nonprim = NULL;
//     cJSON *udm_group_id = NULL;
//     cJSON *routing_indicator = NULL;
//     cJSON *cell_cag_info = NULL;
//     OpenAPI_list_t *cell_cag_infoList = NULL;
//     cJSON *n5gc_ind = NULL;
//     cJSON *supported_features = NULL;
//     cJSON *nswo_ind = NULL;
//     cJSON *disaster_roaming_ind = NULL;
//     cJSON *onboarding_ind = NULL;
//     supi_or_suci = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "supiOrSuci");
//     if (!supi_or_suci) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [supi_or_suci]");
//         goto end;
//     }
//     if (!cJSON_IsString(supi_or_suci)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [supi_or_suci]");
//         goto end;
//     }

//     serving_network_name = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "servingNetworkName");
//     if (!serving_network_name) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }
//     if (!cJSON_IsString(serving_network_name)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [serving_network_name]");
//         goto end;
//     }

//     resynchronization_info = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "resynchronizationInfo");
//     if (resynchronization_info) {
//     resynchronization_info_local_nonprim = OpenAPI_resynchronization_info_parseFromJSON(resynchronization_info);
//     if (!resynchronization_info_local_nonprim) {
//         ogs_error("OpenAPI_resynchronization_info_parseFromJSON failed [resynchronization_info]");
//         goto end;
//     }
//     }

//     pei = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "pei");
//     if (pei) {
//     if (!cJSON_IsString(pei) && !cJSON_IsNull(pei)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [pei]");
//         goto end;
//     }
//     }

//     trace_data = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "traceData");
//     if (trace_data) {
//     trace_data_local_nonprim = OpenAPI_trace_data_parseFromJSON(trace_data);
//     if (!trace_data_local_nonprim) {
//         ogs_error("OpenAPI_trace_data_parseFromJSON failed [trace_data]");
//         goto end;
//     }
//     }

//     udm_group_id = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "udmGroupId");
//     if (udm_group_id) {
//     if (!cJSON_IsString(udm_group_id) && !cJSON_IsNull(udm_group_id)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [udm_group_id]");
//         goto end;
//     }
//     }

//     routing_indicator = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "routingIndicator");
//     if (routing_indicator) {
//     if (!cJSON_IsString(routing_indicator) && !cJSON_IsNull(routing_indicator)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [routing_indicator]");
//         goto end;
//     }
//     }

//     cell_cag_info = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "cellCagInfo");
//     if (cell_cag_info) {
//         cJSON *cell_cag_info_local = NULL;
//         if (!cJSON_IsArray(cell_cag_info)) {
//             ogs_error("OpenAPI_input_data_parseFromJSON() failed [cell_cag_info]");
//             goto end;
//         }

//         cell_cag_infoList = OpenAPI_list_create();

//         cJSON_ArrayForEach(cell_cag_info_local, cell_cag_info) {
//             double *localDouble = NULL;
//             int *localInt = NULL;
//             if (!cJSON_IsString(cell_cag_info_local)) {
//                 ogs_error("OpenAPI_input_data_parseFromJSON() failed [cell_cag_info]");
//                 goto end;
//             }
//             OpenAPI_list_add(cell_cag_infoList, ogs_strdup(cell_cag_info_local->valuestring));
//         }
//     }

//     n5gc_ind = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "n5gcInd");
//     if (n5gc_ind) {
//     if (!cJSON_IsBool(n5gc_ind)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [n5gc_ind]");
//         goto end;
//     }
//     }

//     supported_features = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "supportedFeatures");
//     if (supported_features) {
//     if (!cJSON_IsString(supported_features) && !cJSON_IsNull(supported_features)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [supported_features]");
//         goto end;
//     }
//     }

//     nswo_ind = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "nswoInd");
//     if (nswo_ind) {
//     if (!cJSON_IsBool(nswo_ind)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [nswo_ind]");
//         goto end;
//     }
//     }

//     disaster_roaming_ind = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "disasterRoamingInd");
//     if (disaster_roaming_ind) {
//     if (!cJSON_IsBool(disaster_roaming_ind)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [disaster_roaming_ind]");
//         goto end;
//     }
//     }

//     onboarding_ind = cJSON_GetObjectItemCaseSensitive(input_dataJSON, "onboardingInd");
//     if (onboarding_ind) {
//     if (!cJSON_IsBool(onboarding_ind)) {
//         ogs_error("OpenAPI_input_data_parseFromJSON() failed [onboarding_ind]");
//         goto end;
//     }
//     }

//     input_data_local_var = OpenAPI_input_data_create (
//         ogs_strdup(supi_or_suci->valuestring),
//         ogs_strdup(serving_network_name->valuestring),
//         resynchronization_info ? resynchronization_info_local_nonprim : NULL,
//         pei && !cJSON_IsNull(pei) ? ogs_strdup(pei->valuestring) : NULL,
//         trace_data ? trace_data_local_nonprim : NULL,
//         udm_group_id && !cJSON_IsNull(udm_group_id) ? ogs_strdup(udm_group_id->valuestring) : NULL,
//         routing_indicator && !cJSON_IsNull(routing_indicator) ? ogs_strdup(routing_indicator->valuestring) : NULL,
//         cell_cag_info ? cell_cag_infoList : NULL,
//         n5gc_ind ? true : false,
//         n5gc_ind ? n5gc_ind->valueint : 0,
//         supported_features && !cJSON_IsNull(supported_features) ? ogs_strdup(supported_features->valuestring) : NULL,
//         nswo_ind ? true : false,
//         nswo_ind ? nswo_ind->valueint : 0,
//         disaster_roaming_ind ? true : false,
//         disaster_roaming_ind ? disaster_roaming_ind->valueint : 0,
//         onboarding_ind ? true : false,
//         onboarding_ind ? onboarding_ind->valueint : 0
//     );

//     return input_data_local_var;
// end:
//     if (resynchronization_info_local_nonprim) {
//         OpenAPI_resynchronization_info_free(resynchronization_info_local_nonprim);
//         resynchronization_info_local_nonprim = NULL;
//     }
//     if (trace_data_local_nonprim) {
//         OpenAPI_trace_data_free(trace_data_local_nonprim);
//         trace_data_local_nonprim = NULL;
//     }
//     if (cell_cag_infoList) {
//         OpenAPI_list_for_each(cell_cag_infoList, node) {
//             ogs_free(node->data);
//         }
//         OpenAPI_list_free(cell_cag_infoList);
//         cell_cag_infoList = NULL;
//     }
    return NULL;
}

OpenAPI_input_data_t *OpenAPI_input_data_copy(OpenAPI_input_data_t *dst, OpenAPI_input_data_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);
    item = OpenAPI_input_data_convertToJSON(src);
    if (!item) {
        ogs_error("OpenAPI_input_data_convertToJSON() failed");
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

    OpenAPI_input_data_free(dst);
    dst = OpenAPI_input_data_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
}

