/*
 * usage.h
 *
 * 
 */

#ifndef _OpenAPI_usage_H_
#define _OpenAPI_usage_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_usage_NULL = 0, OpenAPI_usage_UNSUCCESS, OpenAPI_usage_SUCCESS_RESULTS_NOT_USED, OpenAPI_usage_SUCCESS_RESULTS_USED_TO_VERIFY_LOCATION, OpenAPI_usage_SUCCESS_RESULTS_USED_TO_GENERATE_LOCATION, OpenAPI_usage_SUCCESS_METHOD_NOT_DETERMINED } OpenAPI_usage_e;

char* OpenAPI_usage_ToString(OpenAPI_usage_e usage);

OpenAPI_usage_e OpenAPI_usage_FromString(char* usage);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_usage_H_ */

