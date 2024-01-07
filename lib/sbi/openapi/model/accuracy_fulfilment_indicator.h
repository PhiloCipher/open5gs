/*
 * accuracy_fulfilment_indicator.h
 *
 * 
 */

#ifndef _OpenAPI_accuracy_fulfilment_indicator_H_
#define _OpenAPI_accuracy_fulfilment_indicator_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_accuracy_fulfilment_indicator_NULL = 0, OpenAPI_accuracy_fulfilment_indicator_REQUESTED_ACCURACY_FULFILLED, OpenAPI_accuracy_fulfilment_indicator_REQUESTED_ACCURACY_NOT_FULFILLED } OpenAPI_accuracy_fulfilment_indicator_e;

char* OpenAPI_accuracy_fulfilment_indicator_ToString(OpenAPI_accuracy_fulfilment_indicator_e accuracy_fulfilment_indicator);

OpenAPI_accuracy_fulfilment_indicator_e OpenAPI_accuracy_fulfilment_indicator_FromString(char* accuracy_fulfilment_indicator);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_accuracy_fulfilment_indicator_H_ */

