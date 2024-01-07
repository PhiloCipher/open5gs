/*
 * lcs_priority.h
 *
 * 
 */

#ifndef _OpenAPI_lcs_priority_H_
#define _OpenAPI_lcs_priority_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_lcs_priority_NULL = 0, OpenAPI_lcs_priority_HIGHEST_PRIORITY, OpenAPI_lcs_priority_NORMAL_PRIORITY } OpenAPI_lcs_priority_e;

char* OpenAPI_lcs_priority_ToString(OpenAPI_lcs_priority_e lcs_priority);

OpenAPI_lcs_priority_e OpenAPI_lcs_priority_FromString(char* lcs_priority);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_lcs_priority_H_ */

