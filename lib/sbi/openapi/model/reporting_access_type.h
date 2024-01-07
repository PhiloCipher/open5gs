/*
 * reporting_access_type.h
 *
 * 
 */

#ifndef _OpenAPI_reporting_access_type_H_
#define _OpenAPI_reporting_access_type_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_reporting_access_type_NULL = 0, OpenAPI_reporting_access_type_NR, OpenAPI_reporting_access_type_EUTRA_CONNECTED_TO_5GC, OpenAPI_reporting_access_type_NON_3GPP_CONNECTED_TO_5GC, OpenAPI_reporting_access_type_NR_LEO, OpenAPI_reporting_access_type_NR_MEO, OpenAPI_reporting_access_type_NR_GEO, OpenAPI_reporting_access_type_NR_OTHER_SAT } OpenAPI_reporting_access_type_e;

char* OpenAPI_reporting_access_type_ToString(OpenAPI_reporting_access_type_e reporting_access_type);

OpenAPI_reporting_access_type_e OpenAPI_reporting_access_type_FromString(char* reporting_access_type);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_reporting_access_type_H_ */

