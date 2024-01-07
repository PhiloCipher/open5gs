/*
 * occurrence_info.h
 *
 * 
 */

#ifndef _OpenAPI_occurrence_info_H_
#define _OpenAPI_occurrence_info_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_occurrence_info_NULL = 0, OpenAPI_occurrence_info_ONE_TIME_EVENT, OpenAPI_occurrence_info_MULTIPLE_TIME_EVENT } OpenAPI_occurrence_info_e;

char* OpenAPI_occurrence_info_ToString(OpenAPI_occurrence_info_e occurrence_info);

OpenAPI_occurrence_info_e OpenAPI_occurrence_info_FromString(char* occurrence_info);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_occurrence_info_H_ */

