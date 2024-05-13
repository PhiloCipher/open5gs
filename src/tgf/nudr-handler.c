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

#include "nudr-handler.h"

bool tgf_nudr_dr_handle_subscription_authentication(
    tgf_ue_t *tgf_ue, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    char *strerror = NULL;
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;

#if 0
#if 0
    const char *tmp[1] = { "de8ca9df474091fe4e9263c5daa907e9" };
    /* PFCP test */
    const char *tmp[1] = { "cc3766b98a8031a7286a68c7f577ed2e" };
#endif
    /* Xn-Handover */
    const char *tmp[1] = { "5ca0df8c9bb8dbcf3c2a7dd448da1369" };

#if 0
    /* ISSUE-482 */
    const char *tmp[2] = {
        "3a1fa0f51fe50f324f8522b220fc62a2",
        "cc5539bf72824c879e47e73efc885021"
    };
#endif
    static int step = 0;
#endif

    uint8_t autn[OGS_AUTN_LEN];
    uint8_t ik[OGS_KEY_LEN];
    uint8_t ck[OGS_KEY_LEN];
    uint8_t ak[OGS_AK_LEN];
    uint8_t xres[OGS_MAX_RES_LEN];
    size_t xres_len = 8;
    uint8_t xres_star[OGS_MAX_RES_LEN];
    uint8_t kausf[OGS_SHA256_DIGEST_SIZE];

    char rand_string[OGS_KEYSTRLEN(OGS_RAND_LEN)];
    char autn_string[OGS_KEYSTRLEN(OGS_AUTN_LEN)];
    char kausf_string[OGS_KEYSTRLEN(OGS_SHA256_DIGEST_SIZE)];
    char xres_star_string[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];

    OpenAPI_authentication_subscription_t *AuthenticationSubscription = NULL;
    OpenAPI_authentication_info_result_t AuthenticationInfoResult;
    OpenAPI_authentication_vector_t AuthenticationVector;

    ogs_assert(tgf_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    SWITCH(recvmsg->h.resource.component[3])
    CASE(OGS_SBI_RESOURCE_NAME_AUTHENTICATION_SUBSCRIPTION)
        SWITCH(recvmsg->h.method)
        CASE(OGS_SBI_HTTP_METHOD_GET)
            if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_OK) {
                strerror = ogs_msprintf("[%s] HTTP response error [%d]",
                        tgf_ue->suci, recvmsg->res_status);
                ogs_assert(strerror);

                if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_NOT_FOUND)
                    ogs_warn("%s", strerror);
                else
                    ogs_error("%s", strerror);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, recvmsg->res_status, recvmsg, strerror, NULL,
                        recvmsg->ProblemDetails->cause));
                ogs_free(strerror);
                return false;
            }

            AuthenticationSubscription = recvmsg->AuthenticationSubscription;
            if (!AuthenticationSubscription) {
                ogs_error("[%s] No AuthenticationSubscription", tgf_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                        recvmsg, "No AuthenticationSubscription",
                        tgf_ue->suci, NULL));
                return false;
            }

            if (AuthenticationSubscription->authentication_method !=
                    OpenAPI_auth_method_5G_AKA) {
                ogs_error("[%s] Not supported Auth Method [%d]",
                        tgf_ue->suci,
                        AuthenticationSubscription->authentication_method);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_FORBIDDEN,
                        recvmsg, "Not supported Auth Method", tgf_ue->suci,
                        NULL));
                return false;

            }

            if (!AuthenticationSubscription->enc_permanent_key) {
                ogs_error("[%s] No encPermanentKey", tgf_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                        recvmsg, "No encPermanentKey", tgf_ue->suci,
                        NULL));
                return false;
            }
            if (!AuthenticationSubscription->enc_opc_key) {
                ogs_error("[%s] No encPermanentKey", tgf_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "No encPermanentKey", tgf_ue->suci, NULL));
                return false;
            }
            if (!AuthenticationSubscription->authentication_management_field) {
                ogs_error("[%s] No authenticationManagementField",
                        tgf_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "No authenticationManagementField", tgf_ue->suci,
                    NULL));
            return false;
        }
        if (!AuthenticationSubscription->sequence_number) {
            ogs_error("[%s] No SequenceNumber", tgf_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "No SequenceNumber", tgf_ue->suci, NULL));
                return false;
            }
            if (!AuthenticationSubscription->sequence_number->sqn) {
                ogs_error("[%s] No SequenceNumber.sqn", tgf_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "No SequenceNumber.sqn", tgf_ue->suci, NULL));
                return false;
            }

            tgf_ue->auth_type = OpenAPI_auth_type_5G_AKA;

            ogs_ascii_to_hex(
                AuthenticationSubscription->enc_opc_key,
                strlen(AuthenticationSubscription->enc_opc_key),
                tgf_ue->opc, sizeof(tgf_ue->opc));
            ogs_ascii_to_hex(
                AuthenticationSubscription->authentication_management_field,
                strlen(AuthenticationSubscription->
                    authentication_management_field),
                tgf_ue->amf, sizeof(tgf_ue->amf));
            ogs_ascii_to_hex(
                AuthenticationSubscription->enc_permanent_key,
                strlen(AuthenticationSubscription->enc_permanent_key),
                tgf_ue->k, sizeof(tgf_ue->k));
            ogs_ascii_to_hex(
                AuthenticationSubscription->sequence_number->sqn,
                strlen(AuthenticationSubscription->sequence_number->sqn),
                tgf_ue->sqn, sizeof(tgf_ue->sqn));

        CASE(OGS_SBI_HTTP_METHOD_PATCH)
            if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_OK &&
                recvmsg->res_status != OGS_SBI_HTTP_STATUS_NO_CONTENT) {
                strerror = ogs_msprintf("[%s] HTTP response error [%d]",
                        tgf_ue->suci, recvmsg->res_status);
                ogs_assert(strerror);

                ogs_error("%s", strerror);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, recvmsg->res_status, recvmsg, strerror, NULL,
                        recvmsg->ProblemDetails->cause));
                ogs_free(strerror);
                return false;
            }

            memset(&AuthenticationInfoResult,
                    0, sizeof(AuthenticationInfoResult));

            AuthenticationInfoResult.supi = tgf_ue->supi;
            AuthenticationInfoResult.auth_type = tgf_ue->auth_type;

            ogs_random(tgf_ue->rand, OGS_RAND_LEN);
#if 0
            OGS_HEX(tmp[step], strlen(tmp[step]), tgf_ue->rand);
#if 0
            if (step == 0) step = 1; /* For supporting authentication failure */
            else step = 0;
#endif
#endif

            milenage_generate(tgf_ue->opc, tgf_ue->amf, tgf_ue->k, tgf_ue->sqn,
                    tgf_ue->rand, autn, ik, ck, ak, xres, &xres_len);

            ogs_assert(tgf_ue->serving_network_name);

            /* TS33.501 Annex A.2 : Kausf derviation function */
            ogs_kdf_kausf(
                    ck, ik,
                    tgf_ue->serving_network_name, autn,
                    kausf);

            /* TS33.501 Annex A.4 : RES* and XRES* derivation function */
            ogs_kdf_xres_star(
                    ck, ik,
                    tgf_ue->serving_network_name, tgf_ue->rand, xres, xres_len,
                    xres_star);

            memset(&AuthenticationVector, 0, sizeof(AuthenticationVector));
            AuthenticationVector.av_type = OpenAPI_av_type_5G_HE_AKA;

            ogs_hex_to_ascii(tgf_ue->rand, sizeof(tgf_ue->rand),
                    rand_string, sizeof(rand_string));
            AuthenticationVector.rand = rand_string;
            ogs_hex_to_ascii(xres_star, sizeof(xres_star),
                    xres_star_string, sizeof(xres_star_string));
            AuthenticationVector.xres_star = xres_star_string;
            ogs_hex_to_ascii(autn, sizeof(autn),
                    autn_string, sizeof(autn_string));
            AuthenticationVector.autn = autn_string;
            ogs_hex_to_ascii(kausf, sizeof(kausf),
                    kausf_string, sizeof(kausf_string));
            AuthenticationVector.kausf = kausf_string;

            AuthenticationInfoResult.authentication_vector =
                &AuthenticationVector;

            memset(&sendmsg, 0, sizeof(sendmsg));

            ogs_assert(AuthenticationInfoResult.auth_type);
            sendmsg.AuthenticationInfoResult = &AuthenticationInfoResult;

            response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
            ogs_assert(response);
            ogs_assert(true == ogs_sbi_server_send_response(stream, response));

            break;

        DEFAULT
            ogs_error("Invalid HTTP method [%s]", recvmsg->h.method);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_FORBIDDEN, recvmsg,
                    "Invalid HTTP method", recvmsg->h.method, NULL));
            return false;
        END
        break;

    CASE(OGS_SBI_RESOURCE_NAME_AUTHENTICATION_STATUS)
        OpenAPI_auth_event_t *AuthEvent = NULL;

        if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_NO_CONTENT) {
            strerror = ogs_msprintf("[%s] HTTP response error [%d]",
                    tgf_ue->suci, recvmsg->res_status);
            ogs_assert(strerror);

            ogs_error("%s", strerror);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, recvmsg->res_status, recvmsg, strerror, NULL,
                    recvmsg->ProblemDetails->cause));
            ogs_free(strerror);
            return false;
        }

        AuthEvent = tgf_ue->auth_event;
        if (!AuthEvent) {
            ogs_error("[%s] No AuthEvent", tgf_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No AuthEvent", tgf_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->nf_instance_id) {
            ogs_error("[%s] No nfInstanceId", tgf_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No nfInstanceId", tgf_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->success) {
            ogs_error("[%s] No success", tgf_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No success", tgf_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->time_stamp) {
            ogs_error("[%s] No timeStamp", tgf_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No timeStamp", tgf_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->auth_type) {
            ogs_error("[%s] No authType", tgf_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No authType", tgf_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->serving_network_name) {
            ogs_error("[%s] No servingNetworkName", tgf_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No servingNetworkName", tgf_ue->suci, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));

        if (AuthEvent->auth_removal_ind) {
            OpenAPI_auth_event_free(AuthEvent);
            tgf_ue->auth_event = NULL;
            response = ogs_sbi_build_response(&sendmsg,
                    OGS_SBI_HTTP_STATUS_NO_CONTENT);
        } else {
            memset(&header, 0, sizeof(header));
            header.service.name = (char *)OGS_SBI_SERVICE_NAME_NTGF_UEAU;
            header.api.version = (char *)OGS_SBI_API_V1;
            header.resource.component[0] = tgf_ue->supi;
            header.resource.component[1] =
                (char *)OGS_SBI_RESOURCE_NAME_AUTH_EVENTS;
            header.resource.component[2] = tgf_ue->ctx_id;

            sendmsg.http.location = ogs_sbi_server_uri(server, &header);
            sendmsg.AuthEvent = OpenAPI_auth_event_copy(
                    sendmsg.AuthEvent, tgf_ue->auth_event);

            response = ogs_sbi_build_response(&sendmsg,
                    OGS_SBI_HTTP_STATUS_CREATED);
        }
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        ogs_free(sendmsg.http.location);
        OpenAPI_auth_event_free(sendmsg.AuthEvent);
        break;

    DEFAULT
        strerror = ogs_msprintf("[%s] Invalid resource name [%s]",
                tgf_ue->supi, recvmsg->h.resource.component[3]);
        ogs_assert(strerror);

        ogs_error("%s", strerror);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, strerror, NULL, NULL));
        ogs_free(strerror);
        return false;
    END

    return true;
}

bool tgf_nudr_dr_handle_subscription_context(
    tgf_ue_t *tgf_ue, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    char *strerror = NULL;
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;

    int status;

    ogs_assert(tgf_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_NO_CONTENT) {
        ogs_error("[%s] HTTP response error [%d]",
            tgf_ue->supi, recvmsg->res_status);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, recvmsg->res_status,
                NULL, "HTTP response error", tgf_ue->supi,
                recvmsg->ProblemDetails->cause));
        return false;
    }

    SWITCH(recvmsg->h.method)
    CASE(OGS_SBI_HTTP_METHOD_PATCH)
        SWITCH(recvmsg->h.resource.component[3])
        CASE(OGS_SBI_RESOURCE_NAME_AMF_3GPP_ACCESS)
            memset(&sendmsg, 0, sizeof(sendmsg));

            response = ogs_sbi_build_response(
                    &sendmsg, OGS_SBI_HTTP_STATUS_NO_CONTENT);
            ogs_assert(response);
            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
            return true;

        DEFAULT
            strerror = ogs_msprintf("[%s] Invalid resource name [%s]",
                    tgf_ue->supi, recvmsg->h.resource.component[3]);
            ogs_assert(strerror);

            ogs_error("%s", strerror);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, strerror, NULL, NULL));
            ogs_free(strerror);
            return false;
        END
    END

    SWITCH(recvmsg->h.resource.component[3])
    CASE(OGS_SBI_RESOURCE_NAME_AMF_3GPP_ACCESS)
        OpenAPI_amf3_gpp_access_registration_t
            *Amf3GppAccessRegistration = NULL;
        OpenAPI_guami_t *Guami = NULL;

        Amf3GppAccessRegistration = tgf_ue->amf_3gpp_access_registration;

        if (!Amf3GppAccessRegistration) {
            ogs_error("[%s] No Amf3GppAccessRegistration", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No Amf3GppAccessRegistration", tgf_ue->supi,
                    NULL));
            return false;
        }

        if (!Amf3GppAccessRegistration->amf_instance_id) {
            ogs_error("[%s] No amfInstanceId", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No amfInstanceId", tgf_ue->supi, NULL));
            return false;
        }

        if (!Amf3GppAccessRegistration->dereg_callback_uri) {
            ogs_error("[%s] No dregCallbackUri", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No dregCallbackUri", tgf_ue->supi, NULL));
            return false;
        }

        Guami = Amf3GppAccessRegistration->guami;
        if (!Guami) {
            ogs_error("[%s] No Guami", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No Guami", tgf_ue->supi, NULL));
            return false;
        }

        if (!Guami->amf_id) {
            ogs_error("[%s] No Guami.AmfId", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No Guami.AmfId", tgf_ue->supi, NULL));
            return false;
        }

        if (!Guami->plmn_id) {
            ogs_error("[%s] No PlmnId", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No PlmnId", tgf_ue->supi, NULL));
            return false;
        }

        if (!Guami->plmn_id->mnc) {
            ogs_error("[%s] No PlmnId.Mnc", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No PlmnId.Mnc", tgf_ue->supi, NULL));
            return false;
        }

        if (!Guami->plmn_id->mcc) {
            ogs_error("[%s] No PlmnId.Mcc", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No PlmnId.Mcc", tgf_ue->supi, NULL));
            return false;
        }

        if (!Amf3GppAccessRegistration->rat_type) {
            ogs_error("[%s] No RatType", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No RatType", tgf_ue->supi, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));

        memset(&header, 0, sizeof(header));
        header.service.name = (char *)OGS_SBI_SERVICE_NAME_NTGF_UECM;
        header.api.version = (char *)OGS_SBI_API_V1;
        header.resource.component[0] = tgf_ue->supi;
        header.resource.component[1] =
            (char *)OGS_SBI_RESOURCE_NAME_REGISTRATIONS;
        header.resource.component[2] =
            (char *)OGS_SBI_RESOURCE_NAME_AMF_3GPP_ACCESS;

        if (tgf_ue->amf_instance_id &&
            strcmp(tgf_ue->amf_instance_id,
                Amf3GppAccessRegistration->amf_instance_id) == 0) {

            status = OGS_SBI_HTTP_STATUS_OK;

        } else {

            if (tgf_ue->amf_instance_id)
                ogs_free(tgf_ue->amf_instance_id);
            tgf_ue->amf_instance_id =
                ogs_strdup(Amf3GppAccessRegistration->amf_instance_id);
            ogs_assert(tgf_ue->amf_instance_id);

            status = OGS_SBI_HTTP_STATUS_CREATED;
        }


        if (status == OGS_SBI_HTTP_STATUS_CREATED)
            sendmsg.http.location = ogs_sbi_server_uri(server, &header);

        sendmsg.Amf3GppAccessRegistration =
            OpenAPI_amf3_gpp_access_registration_copy(
                sendmsg.Amf3GppAccessRegistration,
                    tgf_ue->amf_3gpp_access_registration);

        response = ogs_sbi_build_response(&sendmsg, status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        ogs_free(sendmsg.http.location);
        OpenAPI_amf3_gpp_access_registration_free(
                sendmsg.Amf3GppAccessRegistration);
        break;

    DEFAULT
        strerror = ogs_msprintf("[%s] Invalid resource name [%s]",
                tgf_ue->supi, recvmsg->h.resource.component[3]);
        ogs_assert(strerror);

        ogs_error("%s", strerror);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, strerror, NULL, NULL));
        ogs_free(strerror);
        return false;
    END

    return true;
}

bool tgf_nudr_dr_handle_subscription_provisioned(
    tgf_ue_t *tgf_ue, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    char *strerror = NULL;
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(tgf_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    SWITCH(recvmsg->h.resource.component[4])
    CASE(OGS_SBI_RESOURCE_NAME_AM_DATA)
        OpenAPI_access_and_mobility_subscription_data_t
            *AccessAndMobilitySubscriptionData = NULL;

        AccessAndMobilitySubscriptionData =
            recvmsg->AccessAndMobilitySubscriptionData;
        if (!AccessAndMobilitySubscriptionData) {
            ogs_error("[%s] No AccessAndMobilitySubscriptionData",
                    tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No AccessAndMobilitySubscriptionData",
                    tgf_ue->supi, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));

        sendmsg.AccessAndMobilitySubscriptionData =
            OpenAPI_access_and_mobility_subscription_data_copy(
                sendmsg.AccessAndMobilitySubscriptionData,
                    recvmsg->AccessAndMobilitySubscriptionData);

        response = ogs_sbi_build_response(&sendmsg, recvmsg->res_status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        OpenAPI_access_and_mobility_subscription_data_free(
                sendmsg.AccessAndMobilitySubscriptionData);
        break;

    CASE(OGS_SBI_RESOURCE_NAME_SMF_SELECTION_SUBSCRIPTION_DATA)
        OpenAPI_smf_selection_subscription_data_t *SmfSelectionSubscriptionData;

        SmfSelectionSubscriptionData = recvmsg->SmfSelectionSubscriptionData;
        if (!SmfSelectionSubscriptionData) {
            ogs_error("[%s] No SmfSelectionSubscriptionData", tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No SmfSelectionSubscriptionData",
                    tgf_ue->supi, NULL));
            return false;
        }

        memset(&SmfSelectionSubscriptionData, 0,
                sizeof(SmfSelectionSubscriptionData));

        memset(&sendmsg, 0, sizeof(sendmsg));

        sendmsg.SmfSelectionSubscriptionData =
            OpenAPI_smf_selection_subscription_data_copy(
                sendmsg.SmfSelectionSubscriptionData,
                    recvmsg->SmfSelectionSubscriptionData);

        response = ogs_sbi_build_response(&sendmsg, recvmsg->res_status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        OpenAPI_smf_selection_subscription_data_free(
                sendmsg.SmfSelectionSubscriptionData);
        break;

    CASE(OGS_SBI_RESOURCE_NAME_SM_DATA)
        OpenAPI_lnode_t *node;

        if ((!recvmsg->SessionManagementSubscriptionDataList) ||
            (recvmsg->SessionManagementSubscriptionDataList->count == 0)) {
            ogs_error("[%s] No SessionManagementSubscriptionData",
                    tgf_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No SessionManagementSubscriptionData",
                    tgf_ue->supi, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));
        sendmsg.SessionManagementSubscriptionDataList = OpenAPI_list_create();

        OpenAPI_list_for_each(recvmsg->SessionManagementSubscriptionDataList, node)
        {
            OpenAPI_session_management_subscription_data_t *item = NULL;

            item = OpenAPI_session_management_subscription_data_copy(item, node->data);
            if (!item) {
                ogs_error("OpenAPI_session_management_subscription_data_copy() "
                        "failed");
                continue;
            }
            OpenAPI_list_add(sendmsg.SessionManagementSubscriptionDataList, item);
        }

        response = ogs_sbi_build_response(&sendmsg, recvmsg->res_status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        OpenAPI_list_for_each(sendmsg.SessionManagementSubscriptionDataList, node)
            OpenAPI_session_management_subscription_data_free(node->data);
        OpenAPI_list_free(sendmsg.SessionManagementSubscriptionDataList);

        break;

    DEFAULT
        strerror = ogs_msprintf("[%s] Invalid resource name [%s]",
                tgf_ue->supi, recvmsg->h.resource.component[3]);
        ogs_assert(strerror);

        ogs_error("%s", strerror);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, strerror, NULL, NULL));
        ogs_free(strerror);
        return false;
    END

    return true;
}

bool tgf_nudr_dr_handle_smf_registration(
    tgf_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    tgf_ue_t *tgf_ue = NULL;

    char *strerror = NULL;
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;

    int status;

    ogs_assert(sess);
    tgf_ue = sess->tgf_ue;
    ogs_assert(tgf_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_NO_CONTENT) {
        ogs_error("[%s:%d] HTTP response error [%d]",
            tgf_ue->supi, sess->psi, recvmsg->res_status);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, recvmsg->res_status,
                NULL, "HTTP response error", tgf_ue->supi,
                recvmsg->ProblemDetails->cause));
        return false;
    }

    SWITCH(recvmsg->h.resource.component[3])
    CASE(OGS_SBI_RESOURCE_NAME_SMF_REGISTRATIONS)
        SWITCH(recvmsg->h.method)
        CASE(OGS_SBI_HTTP_METHOD_PUT)
            OpenAPI_smf_registration_t *SmfRegistration = NULL;

            SmfRegistration = sess->smf_registration;

            if (!SmfRegistration) {
                ogs_error("[%s:%d] No SmfRegistration", tgf_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No SmfRegistration", tgf_ue->supi, NULL));
                return false;
            }

            if (!SmfRegistration->smf_instance_id) {
                ogs_error("[%s:%d] No smfInstanceId", tgf_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No smfInstanceId", tgf_ue->supi, NULL));
                return false;
            }

            if (!SmfRegistration->pdu_session_id) {
                ogs_error("[%s:%d] No pduSessionId", tgf_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No pduSessionId", tgf_ue->supi,
                        NULL));
                return false;
            }

            if (!SmfRegistration->single_nssai ||
                    !SmfRegistration->single_nssai->sst) {
                ogs_error("[%s:%d] No singleNssai", tgf_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No singleNssai", tgf_ue->supi, NULL));
                return false;
            }

            if (!SmfRegistration->dnn) {
                ogs_error("[%s:%d] No dnn", tgf_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No dnn", tgf_ue->supi, NULL));
                return false;
            }

            if (!SmfRegistration->plmn_id ||
                    !SmfRegistration->plmn_id->mcc ||
                    !SmfRegistration->plmn_id->mnc) {
                ogs_error("[%s:%d] No plmnId", tgf_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No plmnId", tgf_ue->supi, NULL));
                return false;
            }

            memset(&sendmsg, 0, sizeof(sendmsg));

            memset(&header, 0, sizeof(header));
            header.service.name = (char *)OGS_SBI_SERVICE_NAME_NTGF_UECM;
            header.api.version = (char *)OGS_SBI_API_V1;
            header.resource.component[0] = tgf_ue->supi;
            header.resource.component[1] =
                (char *)OGS_SBI_RESOURCE_NAME_REGISTRATIONS;
            header.resource.component[2] =
                (char *)OGS_SBI_RESOURCE_NAME_SMF_REGISTRATIONS;
            header.resource.component[3] = ogs_msprintf("%d", sess->psi);

            if (sess->smf_instance_id &&
                strcmp(sess->smf_instance_id,
                    SmfRegistration->smf_instance_id) == 0) {

                status = OGS_SBI_HTTP_STATUS_OK;

            } else {

                if (sess->smf_instance_id)
                    ogs_free(sess->smf_instance_id);
                sess->smf_instance_id =
                    ogs_strdup(SmfRegistration->smf_instance_id);
                ogs_assert(sess->smf_instance_id);

                status = OGS_SBI_HTTP_STATUS_CREATED;
            }

            if (status == OGS_SBI_HTTP_STATUS_CREATED)
                sendmsg.http.location = ogs_sbi_server_uri(server, &header);

            sendmsg.SmfRegistration = OpenAPI_smf_registration_copy(
                    sendmsg.SmfRegistration, sess->smf_registration);

            response = ogs_sbi_build_response(&sendmsg, status);
            ogs_assert(response);
            ogs_assert(true == ogs_sbi_server_send_response(stream, response));

            ogs_free(header.resource.component[3]);
            ogs_free(sendmsg.http.location);
            OpenAPI_smf_registration_free(sendmsg.SmfRegistration);
            break;

        CASE(OGS_SBI_HTTP_METHOD_DELETE)
            ogs_assert(true == ogs_sbi_send_http_status_no_content(stream));
            break;

        DEFAULT
            ogs_error("[%s:%d] Invalid HTTP method [%s]",
                    tgf_ue->suci, sess->psi, recvmsg->h.method);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_FORBIDDEN, recvmsg,
                    "Invalid HTTP method", recvmsg->h.method, NULL));
        END
        break;

    DEFAULT
        strerror = ogs_msprintf("[%s:%d] Invalid resource name [%s]",
                tgf_ue->supi, sess->psi, recvmsg->h.resource.component[3]);
        ogs_assert(strerror);

        ogs_error("%s", strerror);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, strerror, NULL, NULL));
        ogs_free(strerror);
        return false;
    END

    return true;
}
