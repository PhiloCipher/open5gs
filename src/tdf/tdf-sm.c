/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

void tdf_state_initial(ogs_fsm_t *s, tdf_event_t *e)
{
    tdf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &tdf_state_operational);
}

void tdf_state_final(ogs_fsm_t *s, tdf_event_t *e)
{
    tdf_sm_debug(e);

    ogs_assert(s);
}

void tdf_state_operational(ogs_fsm_t *s, tdf_event_t *e)
{
    int rv;

    ogs_sbi_stream_t *stream = NULL;
    ogs_sbi_request_t *request = NULL;

    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_subscription_data_t *subscription_data = NULL;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_message_t message;

    tdf_sm_debug(e);

    ogs_assert(s);
    ogs_ad("TDF state %d: %s", e->h.id, tdf_event_get_name(e));

    switch (e->h.id) {
    case OGS_FSM_ENTRY_SIG:
        ogs_msleep(3000);
        func("imsi-999700000021309");
        tdf_event();
        //ogs_sbi_message_t message2;
        //ogs_sbi_request_t *request2 = NULL;
        // ogs_sbi_server_handler(request2, data);

        
        break;

    case OGS_FSM_EXIT_SIG:
        break;

    case OGS_EVENT_SBI_SERVER:
        request = e->h.sbi.request;
        ogs_assert(request);
        stream = e->h.sbi.data;
        ogs_assert(stream);

        rv = ogs_sbi_parse_request(&message, request);
        if (rv != OGS_OK) {
            /* 'message' buffer is released in ogs_sbi_parse_request() */
            ogs_error("cannot parse HTTP message");
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    NULL, "cannot parse HTTP message", NULL));
            break;
        }

        if (strcmp(message.h.api.version, OGS_SBI_API_V2) != 0) {
            ogs_error("Not supported version [%s]", message.h.api.version);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    &message, "Not supported version", NULL));
            ogs_sbi_message_free(&message);
            break;
        }
        ogs_ad("TDF OGS_EVENT_SBI_SERVER: %s", message.h.service.name);

        SWITCH(message.h.service.name)
        CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM)

            SWITCH(message.h.resource.component[0])
            CASE(OGS_SBI_RESOURCE_NAME_NF_STATUS_NOTIFY)
                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)
                    ogs_nnrf_nfm_handle_nf_status_notify(stream, &message);
                    break;

                DEFAULT
                    ogs_error("Invalid HTTP method [%s]",
                            message.h.method);
                    ogs_assert(true ==
                        ogs_sbi_server_send_error(stream,
                            OGS_SBI_HTTP_STATUS_FORBIDDEN,
                            &message, "Invalid HTTP method", message.h.method));
                END
                break;

            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message.h.resource.component[0]);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_BAD_REQUEST, &message,
                        "Unknown resource name",
                        message.h.resource.component[0]));
            END
            break;

        CASE(OGS_SBI_SERVICE_NAME_NTDF_FIRST)
            ogs_ad("TDF OGS_SBI_SERVICE_NAME_NTDF_FIRST: %s", message.h.resource.component[0]);
            SWITCH(message.h.resource.component[0])
            CASE(OGS_SBI_RESOURCE_NAME_SUBSCRIPTION_DATA)
                SWITCH(message.h.resource.component[2])
                CASE(OGS_SBI_RESOURCE_NAME_AUTHENTICATION_DATA)
                    tdf_ntdf_dr_handle_subscription_authentication(
                            stream, &message);
                    break;

                CASE(OGS_SBI_RESOURCE_NAME_CONTEXT_DATA)
                    tdf_ntdf_dr_handle_subscription_context(stream, &message);
                    break;

                DEFAULT
                    SWITCH(message.h.resource.component[3])
                    CASE(OGS_SBI_RESOURCE_NAME_PROVISIONED_DATA)
                        SWITCH(message.h.method)
                        CASE(OGS_SBI_HTTP_METHOD_GET)
                            tdf_ntdf_dr_handle_subscription_provisioned(
                                    stream, &message);
                            break;
                        DEFAULT
                            ogs_error("Invalid HTTP method [%s]",
                                    message.h.method);
                            ogs_assert(true ==
                                ogs_sbi_server_send_error(stream,
                                    OGS_SBI_HTTP_STATUS_FORBIDDEN,
                                    &message, "Invalid HTTP method",
                                    message.h.method));
                        END
                        break;
                    DEFAULT
                        ogs_error("Invalid resource name [%s]",
                                message.h.resource.component[2]);
                        ogs_assert(true ==
                            ogs_sbi_server_send_error(stream,
                                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                                &message, "Unknown resource name",
                                message.h.resource.component[2]));
                    END
                END
                break;

            CASE(OGS_SBI_RESOURCE_NAME_POLICY_DATA)
                tdf_ntdf_dr_handle_policy_data(stream, &message);
                break;

            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message.h.resource.component[0]);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        &message, "Unknown resource name",
                        message.h.resource.component[0]));
            END
            break;

        DEFAULT
            ogs_error("Invalid API name [%s]", message.h.service.name);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_BAD_REQUEST, &message,
                    "Invalid API name", message.h.resource.component[0]));
        END

        /* In lib/sbi/server.c, notify_completed() releases 'request' buffer. */
        ogs_sbi_message_free(&message);
        break;

    case OGS_EVENT_SBI_CLIENT:
        ogs_assert(e);

        response = e->h.sbi.response;
        ogs_assert(response);
        rv = ogs_sbi_parse_response(&message, response);
        if (rv != OGS_OK) {
            ogs_error("cannot parse HTTP response");
            ogs_sbi_message_free(&message);
            ogs_sbi_response_free(response);
            break;
        }

        if (strcmp(message.h.api.version, OGS_SBI_API_V1) != 0) {
            ogs_error("Not supported version [%s]", message.h.api.version);
            ogs_sbi_message_free(&message);
            ogs_sbi_response_free(response);
            break;
        }
        ogs_ad("TDF OGS_EVENT_SBI_CLIENT: %s", message.h.service.name);

        SWITCH(message.h.service.name)
        CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM)

            SWITCH(message.h.resource.component[0])
            CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)
                nf_instance = e->h.sbi.data;
                ogs_assert(nf_instance);
                ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

                e->h.sbi.message = &message;
                ogs_fsm_dispatch(&nf_instance->sm, e);
                break;

            CASE(OGS_SBI_RESOURCE_NAME_SUBSCRIPTIONS)
                subscription_data = e->h.sbi.data;
                ogs_assert(subscription_data);

                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)
                    if (message.res_status == OGS_SBI_HTTP_STATUS_CREATED ||
                        message.res_status == OGS_SBI_HTTP_STATUS_OK) {
                        ogs_nnrf_nfm_handle_nf_status_subscribe(
                                subscription_data, &message);
                    } else {
                        ogs_error("HTTP response error : %d",
                                message.res_status);
                    }
                    break;

                CASE(OGS_SBI_HTTP_METHOD_PATCH)
                    if (message.res_status == OGS_SBI_HTTP_STATUS_OK ||
                        message.res_status == OGS_SBI_HTTP_STATUS_NO_CONTENT) {
                        ogs_nnrf_nfm_handle_nf_status_update(
                                subscription_data, &message);
                    } else {
                        ogs_error("[%s] HTTP response error [%d]",
                                subscription_data->id ?
                                    subscription_data->id : "Unknown",
                                message.res_status);
                    }
                    break;

                CASE(OGS_SBI_HTTP_METHOD_DELETE)
                    if (message.res_status ==
                            OGS_SBI_HTTP_STATUS_NO_CONTENT) {
                        ogs_sbi_subscription_data_remove(subscription_data);
                    } else {
                        ogs_error("[%s] HTTP response error [%d]",
                                subscription_data->id ?
                                    subscription_data->id : "Unknown",
                                message.res_status);
                    }
                    break;

                DEFAULT
                    ogs_error("[%s] Invalid HTTP method [%s]",
                            subscription_data->id, message.h.method);
                    ogs_assert_if_reached();
                END
                break;
            
            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message.h.resource.component[0]);
                ogs_assert_if_reached();
            END
            break;

        CASE(OGS_SBI_SERVICE_NAME_NUDM_REPORT)
            tdf_ue_t* tdf_ue = tdf_ue_find_by_suti(message.h.resource.component[0]);
            if (!tdf_ue){
                tdf_ue = tdf_ue_add(message.h.resource.component[0]);
                ogs_assert(tdf_ue);
            }

            int i;
            for (i = 0; i < OGS_KEY_LEN; i++)
            {
                tdf_ue->udm_ue->opc[i] = message.udm_ue->opc[i];
            }
            char opc_string[2*OGS_RAND_LEN];
            ogs_hex_to_ascii(tdf_ue->udm_ue->opc, sizeof(tdf_ue->udm_ue->opc),
                    opc_string, sizeof(opc_string));
            ogs_tmp("opc is %s", opc_string);
            ogs_sbi_xact_remove(e->h.sbi.data);

            break;

        CASE(OGS_SBI_SERVICE_NAME_NAUSF_REPORT)
            tdf_ue_t* tdf_ue = tdf_ue_find_by_suti(
                        message.h.resource.component[0]);

            if (!tdf_ue) {
                tdf_ue = tdf_ue_add(message.h.resource.component[0]);
                ogs_assert(tdf_ue);
                }
            tdf_ue->ausf_ue->auth_type = message.ausf_ue->auth_type;
            tdf_ue->ausf_ue->serving_network_name = ogs_strdup(message.ausf_ue->serving_network_name);
            tdf_ue->ausf_ue->suci = message.ausf_ue->suci;
            ogs_tmp("serving_network_name is %s", tdf_ue->ausf_ue->serving_network_name);
            //ogs_tmp("serving_network_name is %s", message.ausf_ue->serving_network_name);
            ogs_sbi_xact_remove(e->h.sbi.data);
            // func("imsi-999700000021309");
            break;

        CASE(OGS_SBI_SERVICE_NAME_NSMF_REPORT)
            tdf_ue_t* tdf_ue = tdf_ue_find_by_suti(
                        message.h.resource.component[0]);

            if (!tdf_ue) {
                tdf_ue = tdf_ue_add(message.h.resource.component[0]);
                ogs_assert(tdf_ue);
                }
            tdf_ue->smf_ue->supi = message.smf_ue->supi;

            ogs_tmp("supi is %s", tdf_ue->smf_ue->supi);
            ogs_sbi_xact_remove(e->h.sbi.data);
            break;

        CASE(OGS_SBI_SERVICE_NAME_NLMF_LOC)
            tdf_ue_t* tdf_ue = tdf_ue_find_by_suti(
                        message.h.resource.component[0]);

            if (!tdf_ue) {
                tdf_ue = tdf_ue_add(message.h.resource.component[0]);
                ogs_assert(tdf_ue);
                }

            ogs_tmp("location is null");
            ogs_sbi_xact_remove(e->h.sbi.data);
            break;

        DEFAULT
            ogs_error("Invalid API name [%s]", message.h.service.name);
            ogs_assert_if_reached();
        END

        ogs_sbi_message_free(&message);
        ogs_sbi_response_free(response);
        break;

    case OGS_EVENT_SBI_TIMER:
        ogs_assert(e);

        switch(e->h.timer_id) {
        case OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL:
        case OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL:
        case OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT:
        case OGS_TIMER_NF_INSTANCE_VALIDITY:
            nf_instance = e->h.sbi.data;
            ogs_assert(nf_instance);
            ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

            ogs_fsm_dispatch(&nf_instance->sm, e);
            if (OGS_FSM_CHECK(&nf_instance->sm, ogs_sbi_nf_state_exception))
                ogs_error("[%s] State machine exception [%d]",
                        nf_instance->id, e->h.timer_id);
            break;

        case OGS_TIMER_SUBSCRIPTION_VALIDITY:
            subscription_data = e->h.sbi.data;
            ogs_assert(subscription_data);

            ogs_assert(true ==
                ogs_nnrf_nfm_send_nf_status_subscribe(
                    ogs_sbi_self()->nf_instance->nf_type,
                    subscription_data->req_nf_instance_id,
                    subscription_data->subscr_cond.nf_type,
                    subscription_data->subscr_cond.service_name));

            ogs_error("[%s] Subscription validity expired",
                subscription_data->id);
            ogs_sbi_subscription_data_remove(subscription_data);
            break;

        case OGS_TIMER_SUBSCRIPTION_PATCH:
            subscription_data = e->h.sbi.data;
            ogs_assert(subscription_data);

            ogs_assert(true ==
                ogs_nnrf_nfm_send_nf_status_update(subscription_data));

            ogs_info("[%s] Need to update Subscription",
                    subscription_data->id);
            break;

        default:
            ogs_error("Unknown timer[%s:%d]",
                    ogs_timer_get_name(e->h.timer_id), e->h.timer_id);
        }
        break;

    default:
        ogs_error("No handler for event %s", tdf_event_get_name(e));
        break;
    }
}
