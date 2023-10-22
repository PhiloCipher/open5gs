/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "nudm-build.h"

ogs_sbi_request_t *tdf_nlmf_location_build_determine_location(
        tdf_ue_t *tdf_ue, void *data)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;

    ogs_assert(tdf_ue);

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    message.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NLMF_LOC;
    message.h.api.version = (char *)OGS_SBI_API_V1;
    message.h.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_DETERMINE_LOCATION;

    //OpenAPI_input_data_t InputData;
    //memset(&InputData, 0, sizeof(InputData));

    //message.InputData = &InputData;

    request = ogs_sbi_build_request(&message);
    ogs_assert(request);

    return request;
}



ogs_sbi_request_t *tdf_nudm_report_build_ue_info(
        tdf_ue_t *tdf_ue, void *data)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;

    ogs_assert(tdf_ue);
    //ogs_assert(amf_ue->supi);
    //ogs_assert(amf_ue->data_change_subscription_id);

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_PUT;
    message.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NUDM_REPORT;
    message.h.api.version = (char *)OGS_SBI_API_V2;
    message.h.resource.component[0] = tdf_ue->supi;
    //message.h.resource.component[1] =
            (char *)OGS_SBI_RESOURCE_NAME_SDM_SUBSCRIPTIONS;
    //message.h.resource.component[2] = amf_ue->data_change_subscription_id;
    OpenAPI_sm_context_update_data_t SmContextUpdateData;
    memset(&SmContextUpdateData, 0, sizeof(SmContextUpdateData));
        SmContextUpdateData.is_failed_to_be_switched = true; // TODO, reveresed!! ogs bug?
        SmContextUpdateData.ma_nw_upgrade_ind = 3; 
        ogs_tmp("is_failed_to_be_switched");
    message.SmContextUpdateData = &SmContextUpdateData;
    SmContextUpdateData.an_type_can_be_changed = 0;
    
    //OpenAPI_auth_event_t AuthEvent;
    //memset(&AuthEvent, 0, sizeof(AuthEvent));
    //message.AuthEvent = &AuthEvent;
    request = ogs_sbi_build_request(&message);
    ogs_expect(request);

    return request;
}