
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "usage.h"

char* OpenAPI_usage_ToString(OpenAPI_usage_e usage)
{
    const char *usageArray[] =  { "NULL", "UNSUCCESS", "SUCCESS_RESULTS_NOT_USED", "SUCCESS_RESULTS_USED_TO_VERIFY_LOCATION", "SUCCESS_RESULTS_USED_TO_GENERATE_LOCATION", "SUCCESS_METHOD_NOT_DETERMINED" };
    size_t sizeofArray = sizeof(usageArray) / sizeof(usageArray[0]);
    if (usage < sizeofArray)
        return (char *)usageArray[usage];
    else
        return (char *)"Unknown";
}

OpenAPI_usage_e OpenAPI_usage_FromString(char* usage)
{
    int stringToReturn = 0;
    const char *usageArray[] =  { "NULL", "UNSUCCESS", "SUCCESS_RESULTS_NOT_USED", "SUCCESS_RESULTS_USED_TO_VERIFY_LOCATION", "SUCCESS_RESULTS_USED_TO_GENERATE_LOCATION", "SUCCESS_METHOD_NOT_DETERMINED" };
    size_t sizeofArray = sizeof(usageArray) / sizeof(usageArray[0]);
    while (stringToReturn < sizeofArray) {
        if (strcmp(usage, usageArray[stringToReturn]) == 0) {
            return stringToReturn;
        }
        stringToReturn++;
    }
    return 0;
}

