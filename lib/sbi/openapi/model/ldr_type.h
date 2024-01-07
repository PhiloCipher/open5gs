/*
 * ldr_type.h
 *
 * 
 */

#ifndef _OpenAPI_ldr_type_H_
#define _OpenAPI_ldr_type_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_ldr_type_NULL = 0, OpenAPI_ldr_type_UE_AVAILABLE, OpenAPI_ldr_type_PERIODIC, OpenAPI_ldr_type_ENTERING_INTO_AREA, OpenAPI_ldr_type_LEAVING_FROM_AREA, OpenAPI_ldr_type_BEING_INSIDE_AREA, OpenAPI_ldr_type_MOTION } OpenAPI_ldr_type_e;

char* OpenAPI_ldr_type_ToString(OpenAPI_ldr_type_e ldr_type);

OpenAPI_ldr_type_e OpenAPI_ldr_type_FromString(char* ldr_type);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_ldr_type_H_ */

