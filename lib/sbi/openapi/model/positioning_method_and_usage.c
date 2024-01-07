
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "positioning_method_and_usage.h"

OpenAPI_positioning_method_and_usage_t *OpenAPI_positioning_method_and_usage_create(
    OpenAPI_positioning_method_e method,
    OpenAPI_positioning_mode_e mode,
    OpenAPI_usage_e usage,
    bool is_method_code,
    int method_code
)
{
    OpenAPI_positioning_method_and_usage_t *positioning_method_and_usage_local_var = ogs_malloc(sizeof(OpenAPI_positioning_method_and_usage_t));
    ogs_assert(positioning_method_and_usage_local_var);

    positioning_method_and_usage_local_var->method = method;
    positioning_method_and_usage_local_var->mode = mode;
    positioning_method_and_usage_local_var->usage = usage;
    positioning_method_and_usage_local_var->is_method_code = is_method_code;
    positioning_method_and_usage_local_var->method_code = method_code;

    return positioning_method_and_usage_local_var;
}

void OpenAPI_positioning_method_and_usage_free(OpenAPI_positioning_method_and_usage_t *positioning_method_and_usage)
{
    OpenAPI_lnode_t *node = NULL;

    if (NULL == positioning_method_and_usage) {
        return;
    }
    ogs_free(positioning_method_and_usage);
}

cJSON *OpenAPI_positioning_method_and_usage_convertToJSON(OpenAPI_positioning_method_and_usage_t *positioning_method_and_usage)
{
    cJSON *item = NULL;
    OpenAPI_lnode_t *node = NULL;

    if (positioning_method_and_usage == NULL) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed [PositioningMethodAndUsage]");
        return NULL;
    }

    item = cJSON_CreateObject();
    if (positioning_method_and_usage->method == OpenAPI_positioning_method_NULL) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed [method]");
        return NULL;
    }
    if (cJSON_AddStringToObject(item, "method", OpenAPI_positioning_method_ToString(positioning_method_and_usage->method)) == NULL) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed [method]");
        goto end;
    }

    if (positioning_method_and_usage->mode == OpenAPI_positioning_mode_NULL) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed [mode]");
        return NULL;
    }
    if (cJSON_AddStringToObject(item, "mode", OpenAPI_positioning_mode_ToString(positioning_method_and_usage->mode)) == NULL) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed [mode]");
        goto end;
    }

    if (positioning_method_and_usage->usage == OpenAPI_usage_NULL) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed [usage]");
        return NULL;
    }
    if (cJSON_AddStringToObject(item, "usage", OpenAPI_usage_ToString(positioning_method_and_usage->usage)) == NULL) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed [usage]");
        goto end;
    }

    if (positioning_method_and_usage->is_method_code) {
    if (cJSON_AddNumberToObject(item, "methodCode", positioning_method_and_usage->method_code) == NULL) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed [method_code]");
        goto end;
    }
    }

end:
    return item;
}

OpenAPI_positioning_method_and_usage_t *OpenAPI_positioning_method_and_usage_parseFromJSON(cJSON *positioning_method_and_usageJSON)
{
    OpenAPI_positioning_method_and_usage_t *positioning_method_and_usage_local_var = NULL;
    OpenAPI_lnode_t *node = NULL;
    cJSON *method = NULL;
    OpenAPI_positioning_method_e methodVariable = 0;
    cJSON *mode = NULL;
    OpenAPI_positioning_mode_e modeVariable = 0;
    cJSON *usage = NULL;
    OpenAPI_usage_e usageVariable = 0;
    cJSON *method_code = NULL;
    method = cJSON_GetObjectItemCaseSensitive(positioning_method_and_usageJSON, "method");
    if (!method) {
        ogs_error("OpenAPI_positioning_method_and_usage_parseFromJSON() failed [method]");
        goto end;
    }
    if (!cJSON_IsString(method)) {
        ogs_error("OpenAPI_positioning_method_and_usage_parseFromJSON() failed [method]");
        goto end;
    }
    methodVariable = OpenAPI_positioning_method_FromString(method->valuestring);

    mode = cJSON_GetObjectItemCaseSensitive(positioning_method_and_usageJSON, "mode");
    if (!mode) {
        ogs_error("OpenAPI_positioning_method_and_usage_parseFromJSON() failed [mode]");
        goto end;
    }
    if (!cJSON_IsString(mode)) {
        ogs_error("OpenAPI_positioning_method_and_usage_parseFromJSON() failed [mode]");
        goto end;
    }
    modeVariable = OpenAPI_positioning_mode_FromString(mode->valuestring);

    usage = cJSON_GetObjectItemCaseSensitive(positioning_method_and_usageJSON, "usage");
    if (!usage) {
        ogs_error("OpenAPI_positioning_method_and_usage_parseFromJSON() failed [usage]");
        goto end;
    }
    if (!cJSON_IsString(usage)) {
        ogs_error("OpenAPI_positioning_method_and_usage_parseFromJSON() failed [usage]");
        goto end;
    }
    usageVariable = OpenAPI_usage_FromString(usage->valuestring);

    method_code = cJSON_GetObjectItemCaseSensitive(positioning_method_and_usageJSON, "methodCode");
    if (method_code) {
    if (!cJSON_IsNumber(method_code)) {
        ogs_error("OpenAPI_positioning_method_and_usage_parseFromJSON() failed [method_code]");
        goto end;
    }
    }

    positioning_method_and_usage_local_var = OpenAPI_positioning_method_and_usage_create (
        methodVariable,
        modeVariable,
        usageVariable,
        method_code ? true : false,
        method_code ? method_code->valuedouble : 0
    );

    return positioning_method_and_usage_local_var;
end:
    return NULL;
}

OpenAPI_positioning_method_and_usage_t *OpenAPI_positioning_method_and_usage_copy(OpenAPI_positioning_method_and_usage_t *dst, OpenAPI_positioning_method_and_usage_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);
    item = OpenAPI_positioning_method_and_usage_convertToJSON(src);
    if (!item) {
        ogs_error("OpenAPI_positioning_method_and_usage_convertToJSON() failed");
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

    OpenAPI_positioning_method_and_usage_free(dst);
    dst = OpenAPI_positioning_method_and_usage_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
}

