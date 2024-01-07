/*
 * velocity_requested.h
 *
 * 
 */

#ifndef _OpenAPI_velocity_requested_H_
#define _OpenAPI_velocity_requested_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_velocity_requested_NULL = 0, OpenAPI_velocity_requested_VELOCITY_IS_NOT_REQUESTED, OpenAPI_velocity_requested_VELOCITY_IS_REQUESTED } OpenAPI_velocity_requested_e;

char* OpenAPI_velocity_requested_ToString(OpenAPI_velocity_requested_e velocity_requested);

OpenAPI_velocity_requested_e OpenAPI_velocity_requested_FromString(char* velocity_requested);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_velocity_requested_H_ */

