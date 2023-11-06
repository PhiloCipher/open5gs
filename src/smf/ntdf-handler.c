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


bool smf_nsmf_report_handle_ue_info(
    smf_ue_t *smf_ue, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(smf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);


    memset(&sendmsg, 0, sizeof(sendmsg));
    OpenAPI_smf_ue_t *smf_ue_ie = ogs_malloc(sizeof(OpenAPI_smf_ue_t));
    memset(smf_ue_ie, 0, sizeof(OpenAPI_smf_ue_t));

    sendmsg.smf_ue = smf_ue_ie;

    smf_ue_ie->supi = smf_ue->supi;
    //ogs_list_copy(&smf_ue_ie.sess_list, smf_ue->sess_list);
    // OpenAPI_smf_sess_t *node = NULL;
    char buf1[OGS_ADDRSTRLEN];
    // ogs_list_for_each(&smf_ue->sess_list, node) {   
    // OGS_INET_NTOP(&node->ipv4->addr, buf1);
    // ogs_tmp("IIP is %s", buf1);
    // }


    smf_sess_t *sess;
    smf_ue_ie->sess_list = OpenAPI_list_create();
    ogs_list_for_each(&smf_ue->sess_list, sess) { 
        OpenAPI_smf_sess_t *smf_sess = ogs_malloc(sizeof(OpenAPI_smf_sess_t));
        OGS_INET_NTOP(&sess->ipv4->addr, buf1);
        smf_sess->ipv4 = buf1;
        OpenAPI_list_add(smf_ue_ie->sess_list, smf_sess);
        OGS_INET_NTOP(&sess->ipv4->addr, buf1);
        ogs_tmp("IIP is %s", buf1);
    }
    
    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));


    return true;
}
