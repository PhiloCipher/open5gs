/*
 * ue_location_service_ind.h
 *
 * 
 */

#ifndef _OpenAPI_ue_location_service_ind_H_
#define _OpenAPI_ue_location_service_ind_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_ue_location_service_ind_NULL = 0, OpenAPI_ue_location_service_ind_LOCATION_ESTIMATE, OpenAPI_ue_location_service_ind_LOCATION_ASSISTANCE_DATA } OpenAPI_ue_location_service_ind_e;

char* OpenAPI_ue_location_service_ind_ToString(OpenAPI_ue_location_service_ind_e ue_location_service_ind);

OpenAPI_ue_location_service_ind_e OpenAPI_ue_location_service_ind_FromString(char* ue_location_service_ind);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_ue_location_service_ind_H_ */

