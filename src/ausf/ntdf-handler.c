/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

#include "sbi-path.h"
#include "ntdf-handler.h"


bool ausf_nausf_report_handle_ue_info(
    ausf_ue_t *ausf_ue, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);


    memset(&sendmsg, 0, sizeof(sendmsg));
    OpenAPI_ausf_ue_t ausf_ue_ie;
    memset(&ausf_ue_ie, 0, sizeof(ausf_ue_ie));

    sendmsg.ausf_ue = &ausf_ue_ie;

    ausf_ue_ie.ctx_id = ausf_ue->ctx_id;
    ausf_ue_ie.suci = ausf_ue->suci;
    ausf_ue_ie.supi = ausf_ue->supi;
    ausf_ue_ie.serving_network_name = ausf_ue->serving_network_name;
    ausf_ue_ie.auth_type = ausf_ue->auth_type;
    ausf_ue_ie.auth_events_url = ausf_ue->auth_events_url;
    ausf_ue_ie.auth_result = ausf_ue->auth_result;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));


    return true;
}
