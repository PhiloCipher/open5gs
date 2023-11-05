/*
 * input_data.h
 *
 * Contains the UE id (i.e. SUCI or SUPI) and the Serving Network Name.
 */

#ifndef _OpenAPI_input_data_H_
#define _OpenAPI_input_data_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "resynchronization_info.h"
#include "trace_data.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_input_data_s OpenAPI_input_data_t;
typedef struct OpenAPI_input_data_s {
    OpenAPI_external_client_type_any_of_e external_client_type;
    char *supi;
    char *pei;

} OpenAPI_input_data_t;

OpenAPI_input_data_t *OpenAPI_input_data_create(
    OpenAPI_external_client_type_t external_client_type,
    char *supi,
    char *pei
);
void OpenAPI_input_data_free(OpenAPI_input_data_t *input_data);
OpenAPI_input_data_t *OpenAPI_input_data_parseFromJSON(cJSON *input_dataJSON);
cJSON *OpenAPI_input_data_convertToJSON(OpenAPI_input_data_t *input_data);
OpenAPI_input_data_t *OpenAPI_input_data_copy(OpenAPI_input_data_t *dst, OpenAPI_input_data_t *src);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_input_data_H_ */

