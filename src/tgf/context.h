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

#ifndef TGF_CONTEXT_H
#define TGF_CONTEXT_H

#include "ogs-app.h"
#include "ogs-crypt.h"
#include "ogs-sbi.h"

#include "tgf-sm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __tgf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __tgf_log_domain

typedef struct tgf_context_s {
    ogs_list_t      tgf_ue_list;
    ogs_list_t      sdm_subscription_list;
    ogs_hash_t      *suci_hash;
    ogs_hash_t      *supi_hash;
    ogs_hash_t      *sdm_subscription_id_hash;

} tgf_context_t;

struct tgf_ue_s {
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

    uint8_t k[OGS_KEY_LEN];
    uint8_t opc[OGS_KEY_LEN];
    uint8_t amf[OGS_AMF_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t sqn[OGS_SQN_LEN];

    ogs_guami_t guami;

    OpenAPI_auth_type_e auth_type;
    OpenAPI_rat_type_e rat_type;

    ogs_list_t sess_list;
    ogs_list_t sdm_subscription_list;
};

struct tgf_sess_s {
    ogs_sbi_object_t sbi;
    ogs_fsm_t sm;

    uint8_t psi; /* PDU Session Identity */

    OpenAPI_smf_registration_t *smf_registration;

    char *smf_instance_id;

    /* Related Context */
    tgf_ue_t *tgf_ue;
};

typedef struct tgf_sdm_subscription_s {
    ogs_lnode_t lnode;

    char *id;
    char *data_change_callback_uri;

    tgf_ue_t *tgf_ue;
} tgf_sdm_subscription_t;

void tgf_context_init(void);
void tgf_context_final(void);
tgf_context_t *tgf_self(void);

int tgf_context_parse_config(void);

tgf_ue_t *tgf_ue_add(char *suci);
void tgf_ue_remove(tgf_ue_t *tgf_ue);
void tgf_ue_remove_all(void);
tgf_ue_t *tgf_ue_find_by_suci(char *suci);
tgf_ue_t *tgf_ue_find_by_supi(char *supi);
tgf_ue_t *tgf_ue_find_by_suci_or_supi(char *suci_or_supi);
tgf_ue_t *tgf_ue_find_by_ctx_id(char *ctx_id);

tgf_sess_t *tgf_sess_add(tgf_ue_t *tgf_ue, uint8_t psi);
void tgf_sess_remove(tgf_sess_t *sess);
void tgf_sess_remove_all(tgf_ue_t *tgf_ue);
tgf_sess_t *tgf_sess_find_by_psi(tgf_ue_t *tgf_ue, uint8_t psi);

tgf_ue_t *tgf_ue_cycle(tgf_ue_t *tgf_ue);
tgf_sess_t *tgf_sess_cycle(tgf_sess_t *sess);

tgf_sdm_subscription_t *tgf_sdm_subscription_add(tgf_ue_t *tgf_ue);
void tgf_sdm_subscription_remove(tgf_sdm_subscription_t *subscription);
void tgf_sdm_subscription_remove_all(tgf_ue_t *tgf_ue);
tgf_sdm_subscription_t *tgf_sdm_subscription_find_by_id(char *id);

int get_ue_load(void);

#ifdef __cplusplus
}
#endif

#endif /* TGF_CONTEXT_H */
