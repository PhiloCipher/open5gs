
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "gnss_positioning_method_and_usage.h"

OpenAPI_gnss_positioning_method_and_usage_t *OpenAPI_gnss_positioning_method_and_usage_create(
    OpenAPI_positioning_mode_e mode,
    OpenAPI_gnss_id_e gnss,
    OpenAPI_usage_e usage
)
{
    OpenAPI_gnss_positioning_method_and_usage_t *gnss_positioning_method_and_usage_local_var = ogs_malloc(sizeof(OpenAPI_gnss_positioning_method_and_usage_t));
    ogs_assert(gnss_positioning_method_and_usage_local_var);

    gnss_positioning_method_and_usage_local_var->mode = mode;
    gnss_positioning_method_and_usage_local_var->gnss = gnss;
    gnss_positioning_method_and_usage_local_var->usage = usage;

    return gnss_positioning_method_and_usage_local_var;
}

void OpenAPI_gnss_positioning_method_and_usage_free(OpenAPI_gnss_positioning_method_and_usage_t *gnss_positioning_method_and_usage)
{
    OpenAPI_lnode_t *node = NULL;

    if (NULL == gnss_positioning_method_and_usage) {
        return;
    }
    ogs_free(gnss_positioning_method_and_usage);
}

cJSON *OpenAPI_gnss_positioning_method_and_usage_convertToJSON(OpenAPI_gnss_positioning_method_and_usage_t *gnss_positioning_method_and_usage)
{
    cJSON *item = NULL;
    OpenAPI_lnode_t *node = NULL;

    if (gnss_positioning_method_and_usage == NULL) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_convertToJSON() failed [GnssPositioningMethodAndUsage]");
        return NULL;
    }

    item = cJSON_CreateObject();
    if (gnss_positioning_method_and_usage->mode == OpenAPI_positioning_mode_NULL) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_convertToJSON() failed [mode]");
        return NULL;
    }
    if (cJSON_AddStringToObject(item, "mode", OpenAPI_positioning_mode_ToString(gnss_positioning_method_and_usage->mode)) == NULL) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_convertToJSON() failed [mode]");
        goto end;
    }

    if (gnss_positioning_method_and_usage->gnss == OpenAPI_gnss_id_NULL) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_convertToJSON() failed [gnss]");
        return NULL;
    }
    if (cJSON_AddStringToObject(item, "gnss", OpenAPI_gnss_id_ToString(gnss_positioning_method_and_usage->gnss)) == NULL) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_convertToJSON() failed [gnss]");
        goto end;
    }

    if (gnss_positioning_method_and_usage->usage == OpenAPI_usage_NULL) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_convertToJSON() failed [usage]");
        return NULL;
    }
    if (cJSON_AddStringToObject(item, "usage", OpenAPI_usage_ToString(gnss_positioning_method_and_usage->usage)) == NULL) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_convertToJSON() failed [usage]");
        goto end;
    }

end:
    return item;
}

OpenAPI_gnss_positioning_method_and_usage_t *OpenAPI_gnss_positioning_method_and_usage_parseFromJSON(cJSON *gnss_positioning_method_and_usageJSON)
{
    OpenAPI_gnss_positioning_method_and_usage_t *gnss_positioning_method_and_usage_local_var = NULL;
    OpenAPI_lnode_t *node = NULL;
    cJSON *mode = NULL;
    OpenAPI_positioning_mode_e modeVariable = 0;
    cJSON *gnss = NULL;
    OpenAPI_gnss_id_e gnssVariable = 0;
    cJSON *usage = NULL;
    OpenAPI_usage_e usageVariable = 0;
    mode = cJSON_GetObjectItemCaseSensitive(gnss_positioning_method_and_usageJSON, "mode");
    if (!mode) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_parseFromJSON() failed [mode]");
        goto end;
    }
    if (!cJSON_IsString(mode)) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_parseFromJSON() failed [mode]");
        goto end;
    }
    modeVariable = OpenAPI_positioning_mode_FromString(mode->valuestring);

    gnss = cJSON_GetObjectItemCaseSensitive(gnss_positioning_method_and_usageJSON, "gnss");
    if (!gnss) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_parseFromJSON() failed [gnss]");
        goto end;
    }
    if (!cJSON_IsString(gnss)) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_parseFromJSON() failed [gnss]");
        goto end;
    }
    gnssVariable = OpenAPI_gnss_id_FromString(gnss->valuestring);

    usage = cJSON_GetObjectItemCaseSensitive(gnss_positioning_method_and_usageJSON, "usage");
    if (!usage) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_parseFromJSON() failed [usage]");
        goto end;
    }
    if (!cJSON_IsString(usage)) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_parseFromJSON() failed [usage]");
        goto end;
    }
    usageVariable = OpenAPI_usage_FromString(usage->valuestring);

    gnss_positioning_method_and_usage_local_var = OpenAPI_gnss_positioning_method_and_usage_create (
        modeVariable,
        gnssVariable,
        usageVariable
    );

    return gnss_positioning_method_and_usage_local_var;
end:
    return NULL;
}

OpenAPI_gnss_positioning_method_and_usage_t *OpenAPI_gnss_positioning_method_and_usage_copy(OpenAPI_gnss_positioning_method_and_usage_t *dst, OpenAPI_gnss_positioning_method_and_usage_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);
    item = OpenAPI_gnss_positioning_method_and_usage_convertToJSON(src);
    if (!item) {
        ogs_error("OpenAPI_gnss_positioning_method_and_usage_convertToJSON() failed");
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

    OpenAPI_gnss_positioning_method_and_usage_free(dst);
    dst = OpenAPI_gnss_positioning_method_and_usage_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
}

