/*
 * reporting_area_type.h
 *
 * 
 */

#ifndef _OpenAPI_reporting_area_type_H_
#define _OpenAPI_reporting_area_type_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_reporting_area_type_NULL = 0, OpenAPI_reporting_area_type_EPS_TRACKING_AREA_IDENTITY, OpenAPI_reporting_area_type_E_UTRAN_CELL_GLOBAL_IDENTIFICATION, OpenAPI_reporting_area_type__5GS_TRACKING_AREA_IDENTITY, OpenAPI_reporting_area_type_NR_CELL_GLOBAL_IDENTITY } OpenAPI_reporting_area_type_e;

char* OpenAPI_reporting_area_type_ToString(OpenAPI_reporting_area_type_e reporting_area_type);

OpenAPI_reporting_area_type_e OpenAPI_reporting_area_type_FromString(char* reporting_area_type);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_reporting_area_type_H_ */

