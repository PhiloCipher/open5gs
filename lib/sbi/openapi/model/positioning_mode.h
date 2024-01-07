/*
 * positioning_mode.h
 *
 * 
 */

#ifndef _OpenAPI_positioning_mode_H_
#define _OpenAPI_positioning_mode_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_positioning_mode_NULL = 0, OpenAPI_positioning_mode_UE_BASED, OpenAPI_positioning_mode_UE_ASSISTED, OpenAPI_positioning_mode_CONVENTIONAL } OpenAPI_positioning_mode_e;

char* OpenAPI_positioning_mode_ToString(OpenAPI_positioning_mode_e positioning_mode);

OpenAPI_positioning_mode_e OpenAPI_positioning_mode_FromString(char* positioning_mode);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_positioning_mode_H_ */

