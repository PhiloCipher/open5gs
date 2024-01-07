/*
 * event_class.h
 *
 * 
 */

#ifndef _OpenAPI_event_class_H_
#define _OpenAPI_event_class_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_event_class_NULL = 0, OpenAPI_event_class_SUPPLEMENTARY_SERVICES } OpenAPI_event_class_e;

char* OpenAPI_event_class_ToString(OpenAPI_event_class_e event_class);

OpenAPI_event_class_e OpenAPI_event_class_FromString(char* event_class);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_event_class_H_ */

