/*
 * gnss_id.h
 *
 * 
 */

#ifndef _OpenAPI_gnss_id_H_
#define _OpenAPI_gnss_id_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_gnss_id_NULL = 0, OpenAPI_gnss_id_GPS, OpenAPI_gnss_id_GALILEO, OpenAPI_gnss_id_SBAS, OpenAPI_gnss_id_MODERNIZED_GPS, OpenAPI_gnss_id_QZSS, OpenAPI_gnss_id_GLONASS, OpenAPI_gnss_id_BDS, OpenAPI_gnss_id_NAVIC } OpenAPI_gnss_id_e;

char* OpenAPI_gnss_id_ToString(OpenAPI_gnss_id_e gnss_id);

OpenAPI_gnss_id_e OpenAPI_gnss_id_FromString(char* gnss_id);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_gnss_id_H_ */

