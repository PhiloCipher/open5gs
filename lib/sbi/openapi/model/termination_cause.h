/*
 * termination_cause.h
 *
 * 
 */

#ifndef _OpenAPI_termination_cause_H_
#define _OpenAPI_termination_cause_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OpenAPI_termination_cause_NULL = 0, OpenAPI_termination_cause_TERMINATION_BY_UE, OpenAPI_termination_cause_TERMINATION_BY_NETWORK, OpenAPI_termination_cause_NORMAL_TERMINATION } OpenAPI_termination_cause_e;

char* OpenAPI_termination_cause_ToString(OpenAPI_termination_cause_e termination_cause);

OpenAPI_termination_cause_e OpenAPI_termination_cause_FromString(char* termination_cause);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_termination_cause_H_ */

