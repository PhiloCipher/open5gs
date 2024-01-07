/*
 * reported_event_type.h
 *
 * 
 */

#ifndef _OpenAPI_reported_event_type_H_
#define _OpenAPI_reported_event_type_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_reported_event_type_NULL = 0, OpenAPI_reported_event_type_PERIODIC_EVENT, OpenAPI_reported_event_type_ENTERING_AREA_EVENT, OpenAPI_reported_event_type_LEAVING_AREA_EVENT, OpenAPI_reported_event_type_BEING_INSIDE_AREA_EVENT, OpenAPI_reported_event_type_MOTION_EVENT, OpenAPI_reported_event_type_MAXIMUM_INTERVAL_EXPIRATION_EVENT, OpenAPI_reported_event_type_LOCATION_CANCELLATION_EVENT } OpenAPI_reported_event_type_e;

char* OpenAPI_reported_event_type_ToString(OpenAPI_reported_event_type_e reported_event_type);

OpenAPI_reported_event_type_e OpenAPI_reported_event_type_FromString(char* reported_event_type);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_reported_event_type_H_ */

