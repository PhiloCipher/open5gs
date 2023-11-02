/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef TDF_CONTEXT_H
#define TDF_CONTEXT_H

#include "ogs-app.h"
#include "ogs-dbi.h"
#include "ogs-sbi.h"

#include "tdf-sm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __tdf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __tdf_log_domain

typedef struct tdf_context_s {
    ogs_list_t      tdf_ue_list;
    ogs_hash_t      *suti_hash;

} tdf_context_t;


void tdf_context_init(void);
void tdf_context_final(void);
tdf_context_t *tdf_self(void);

int tdf_context_parse_config(void);


struct udm_ue_s {
    ogs_sbi_object_t sbi;
    ogs_fsm_t sm;

    OpenAPI_auth_event_t *auth_event;
    OpenAPI_amf3_gpp_access_registration_t *amf_3gpp_access_registration;

    char *ctx_id;
    char *suci;
    char *supi;
    char *serving_network_name;

    char *ausf_instance_id;
    char *amf_instance_id;

    char *dereg_callback_uri;
    char *data_change_callback_uri;

    uint8_t k[OGS_KEY_LEN];
    uint8_t opc[OGS_KEY_LEN];
    uint8_t amf[OGS_AMF_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t sqn[OGS_SQN_LEN];

    ogs_guami_t guami;

    OpenAPI_auth_type_e auth_type;
    OpenAPI_rat_type_e rat_type;
};


struct pcf_ue_s {
    ogs_sbi_object_t sbi;
    ogs_fsm_t sm;

    char *association_id;
    char *supi;

    char *notification_uri;
    struct {
        ogs_sbi_client_t *client;
    } namf;

    char *gpsi;
    OpenAPI_access_type_e access_type;
    char *pei;

    ogs_guami_t guami;
    OpenAPI_rat_type_e rat_type;

    /* SBI Features */
    uint64_t am_policy_control_features;

    OpenAPI_policy_association_request_t *policy_association_request;
    OpenAPI_ambr_t *subscribed_ue_ambr;

    ogs_list_t sess_list;
};

struct ausf_ue_s {
    ogs_sbi_object_t sbi;
    ogs_fsm_t sm;

    char *ctx_id;
    char *suci;
    char *supi;
    char *serving_network_name;

    OpenAPI_auth_type_e auth_type;
    char *auth_events_url;
    OpenAPI_auth_result_e auth_result;

    uint8_t rand[OGS_RAND_LEN];
    uint8_t xres_star[OGS_MAX_RES_LEN];
    uint8_t hxres_star[OGS_MAX_RES_LEN];
    uint8_t kausf[OGS_SHA256_DIGEST_SIZE];
    uint8_t kseaf[OGS_SHA256_DIGEST_SIZE];
};

struct tdf_ue_s {
    ogs_sbi_object_t sbi;
    char *suti;
    udm_ue_t *udm_ue;
    pcf_ue_t *pcf_ue;
    ausf_ue_t *ausf_ue;
};

ogs_sbi_request_t *tdf_npcf_am_policy_control_build_delete(tdf_ue_t *tdf_ue, void *data);
void func(char *suti);
int tdf_event(void);
ausf_ue_t *ausf_ue_add(void);
udm_ue_t *udm_ue_add(void);
tdf_ue_t *tdf_ue_add(char *suti);
void tdf_ue_remove(tdf_ue_t *tdf_ue);
void tdf_ue_remove_all(void);
tdf_ue_t *tdf_ue_find_by_suti(char *suti);

#ifdef __cplusplus
}
#endif

#endif /* TDF_CONTEXT_H */
