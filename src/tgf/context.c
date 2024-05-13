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

#include "sbi-path.h"

static tgf_context_t self;

int __tgf_log_domain;

static OGS_POOL(tgf_ue_pool, tgf_ue_t);
static OGS_POOL(tgf_sess_pool, tgf_sess_t);
static OGS_POOL(tgf_sdm_subscription_pool, tgf_sdm_subscription_t);

static int context_initialized = 0;

static int max_num_of_tgf_sdm_subscriptions = 0;

void tgf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize TGF context */
    memset(&self, 0, sizeof(tgf_context_t));

    ogs_log_install_domain(&__tgf_log_domain, "tgf", ogs_core()->log.level);

    ogs_pool_init(&tgf_ue_pool, ogs_global_conf()->max.ue);
    ogs_pool_init(&tgf_sess_pool, ogs_app()->pool.sess);
#define MAX_NUM_OF_TGF_SDM_SUBSCRIPTIONS_PER_UE 4
    max_num_of_tgf_sdm_subscriptions = ogs_global_conf()->max.ue *
            MAX_NUM_OF_TGF_SDM_SUBSCRIPTIONS_PER_UE;
    ogs_pool_init(&tgf_sdm_subscription_pool, max_num_of_tgf_sdm_subscriptions);

    ogs_list_init(&self.tgf_ue_list);
    self.suci_hash = ogs_hash_make();
    ogs_assert(self.suci_hash);
    self.supi_hash = ogs_hash_make();
    ogs_assert(self.supi_hash);

    ogs_list_init(&self.sdm_subscription_list);
    self.sdm_subscription_id_hash = ogs_hash_make();
    ogs_assert(self.sdm_subscription_id_hash);

    context_initialized = 1;
}

void tgf_context_final(void)
{
    ogs_assert(context_initialized == 1);

    tgf_ue_remove_all();

    ogs_assert(self.suci_hash);
    ogs_hash_destroy(self.suci_hash);
    ogs_assert(self.supi_hash);
    ogs_hash_destroy(self.supi_hash);
    ogs_assert(self.sdm_subscription_id_hash);
    ogs_hash_destroy(self.sdm_subscription_id_hash);

    ogs_pool_final(&tgf_ue_pool);
    ogs_pool_final(&tgf_sess_pool);
    ogs_pool_final(&tgf_sdm_subscription_pool);

    context_initialized = 0;
}

tgf_context_t *tgf_self(void)
{
    return &self;
}

static int tgf_context_prepare(void)
{
    return OGS_OK;
}

static int tgf_context_validation(void)
{
    return OGS_OK;
}

int tgf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = tgf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "tgf")) {
            ogs_yaml_iter_t tgf_iter;
            ogs_yaml_iter_recurse(&root_iter, &tgf_iter);
            while (ogs_yaml_iter_next(&tgf_iter)) {
                const char *tgf_key = ogs_yaml_iter_key(&tgf_iter);
                ogs_assert(tgf_key);
                if (!strcmp(tgf_key, "default")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tgf_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tgf_key, "nrf")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tgf_key, "scp")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tgf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tgf_key, "discovery")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tgf_key, "hnet")) {
                    rv = ogs_sbi_context_parse_hnet_config(&tgf_iter);
                    if (rv != OGS_OK) return rv;
                } else
                    ogs_warn("unknown key `%s`", tgf_key);
            }
        }
    }

    rv = tgf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

tgf_ue_t *tgf_ue_add(char *suci)
{
    tgf_event_t e;
    tgf_ue_t *tgf_ue = NULL;

    // ogs_assert(suci);

    // ogs_pool_alloc(&tgf_ue_pool, &tgf_ue);
    // if (!tgf_ue) {
    //     ogs_error("No memory pool [%s]", suci);
    //     return NULL;
    // }
    // memset(tgf_ue, 0, sizeof *tgf_ue);

    // /* SBI Type */
    // tgf_ue->sbi.type = OGS_SBI_OBJ_UE_TYPE;

    // tgf_ue->ctx_id = ogs_msprintf("%d",
    //         (int)ogs_pool_index(&tgf_ue_pool, tgf_ue));
    // if (!tgf_ue->ctx_id) {
    //     ogs_error("No memory for tgf_ue->ctx_id [%s]", suci);
    //     ogs_pool_free(&tgf_ue_pool, tgf_ue);
    //     return NULL;
    // }

    // tgf_ue->suci = ogs_strdup(suci);
    // if (!tgf_ue->suci) {
    //     ogs_error("No memory for tgf_ue->suci [%s]", suci);
    //     ogs_free(tgf_ue->ctx_id);
    //     ogs_pool_free(&tgf_ue_pool, tgf_ue);
    //     return NULL;
    // }

    // tgf_ue->supi = ogs_supi_from_supi_or_suci(tgf_ue->suci);
    // if (!tgf_ue->supi) {
    //     ogs_error("No memory for tgf_ue->supi [%s]", suci);
    //     ogs_free(tgf_ue->suci);
    //     ogs_free(tgf_ue->ctx_id);
    //     ogs_pool_free(&tgf_ue_pool, tgf_ue);
    //     return NULL;
    // }

    // ogs_hash_set(self.suci_hash, tgf_ue->suci, strlen(tgf_ue->suci), tgf_ue);
    // ogs_hash_set(self.supi_hash, tgf_ue->supi, strlen(tgf_ue->supi), tgf_ue);

    // memset(&e, 0, sizeof(e));
    // e.tgf_ue = tgf_ue;
    // ogs_fsm_init(&tgf_ue->sm, tgf_ue_state_initial, tgf_ue_state_final, &e);

    // ogs_list_add(&self.tgf_ue_list, tgf_ue);

    return tgf_ue;
}

void tgf_ue_remove(tgf_ue_t *tgf_ue)
{
    tgf_event_t e;

    ogs_assert(tgf_ue);

    ogs_list_remove(&self.tgf_ue_list, tgf_ue);

    memset(&e, 0, sizeof(e));
    e.tgf_ue = tgf_ue;
    ogs_fsm_fini(&tgf_ue->sm, &e);

    /* Free SBI object memory */
    ogs_sbi_object_free(&tgf_ue->sbi);

    tgf_sess_remove_all(tgf_ue);
    tgf_sdm_subscription_remove_all(tgf_ue);

    OpenAPI_auth_event_free(tgf_ue->auth_event);
    OpenAPI_amf3_gpp_access_registration_free(
            tgf_ue->amf_3gpp_access_registration);

    ogs_assert(tgf_ue->ctx_id);
    ogs_free(tgf_ue->ctx_id);

    ogs_assert(tgf_ue->suci);
    ogs_hash_set(self.suci_hash, tgf_ue->suci, strlen(tgf_ue->suci), NULL);
    ogs_free(tgf_ue->suci);

    ogs_assert(tgf_ue->supi);
    ogs_hash_set(self.supi_hash, tgf_ue->supi, strlen(tgf_ue->supi), NULL);
    ogs_free(tgf_ue->supi);

    if (tgf_ue->serving_network_name)
        ogs_free(tgf_ue->serving_network_name);
    if (tgf_ue->ausf_instance_id)
        ogs_free(tgf_ue->ausf_instance_id);
    if (tgf_ue->amf_instance_id)
        ogs_free(tgf_ue->amf_instance_id);
    if (tgf_ue->dereg_callback_uri)
        ogs_free(tgf_ue->dereg_callback_uri);

    ogs_pool_free(&tgf_ue_pool, tgf_ue);
}

void tgf_ue_remove_all(void)
{
    tgf_ue_t *tgf_ue = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.tgf_ue_list, next, tgf_ue)
        tgf_ue_remove(tgf_ue);
}

tgf_ue_t *tgf_ue_find_by_suci(char *suci)
{
    ogs_assert(suci);
    return (tgf_ue_t *)ogs_hash_get(self.suci_hash, suci, strlen(suci));
}

tgf_ue_t *tgf_ue_find_by_supi(char *supi)
{
    ogs_assert(supi);
    return (tgf_ue_t *)ogs_hash_get(self.supi_hash, supi, strlen(supi));
}

tgf_ue_t *tgf_ue_find_by_suci_or_supi(char *suci_or_supi)
{
    ogs_assert(suci_or_supi);
    if (strncmp(suci_or_supi, "suci-", strlen("suci-")) == 0)
        return tgf_ue_find_by_suci(suci_or_supi);
    else
        return tgf_ue_find_by_supi(suci_or_supi);
}

tgf_ue_t *tgf_ue_find_by_ctx_id(char *ctx_id)
{
    ogs_assert(ctx_id);
    return ogs_pool_find(&tgf_ue_pool, atoll(ctx_id));
}

tgf_sess_t *tgf_sess_add(tgf_ue_t *tgf_ue, uint8_t psi)
{
    tgf_event_t e;
    tgf_sess_t *sess = NULL;

    ogs_assert(tgf_ue);
    ogs_assert(psi != OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED);

    ogs_pool_alloc(&tgf_sess_pool, &sess);
    ogs_assert(sess);
    memset(sess, 0, sizeof *sess);

    /* SBI Type */
    sess->sbi.type = OGS_SBI_OBJ_SESS_TYPE;

    sess->tgf_ue = tgf_ue;
    sess->psi = psi;

    memset(&e, 0, sizeof(e));
    e.sess = sess;
    ogs_fsm_init(&sess->sm, tgf_sess_state_initial, tgf_sess_state_final, &e);

    ogs_list_add(&tgf_ue->sess_list, sess);

    return sess;
}

void tgf_sess_remove(tgf_sess_t *sess)
{
    tgf_event_t e;

    ogs_assert(sess);
    ogs_assert(sess->tgf_ue);

    ogs_list_remove(&sess->tgf_ue->sess_list, sess);

    memset(&e, 0, sizeof(e));
    e.sess = sess;
    ogs_fsm_fini(&sess->sm, &e);

    /* Free SBI object memory */
    if (ogs_list_count(&sess->sbi.xact_list))
        ogs_error("Session transaction [%d]",
                ogs_list_count(&sess->sbi.xact_list));
    ogs_sbi_object_free(&sess->sbi);

    OpenAPI_smf_registration_free(sess->smf_registration);

    if (sess->smf_instance_id)
        ogs_free(sess->smf_instance_id);

    ogs_pool_free(&tgf_sess_pool, sess);
}

void tgf_sess_remove_all(tgf_ue_t *tgf_ue)
{
    tgf_sess_t *sess = NULL, *next_sess = NULL;

    ogs_assert(tgf_ue);

    ogs_list_for_each_safe(&tgf_ue->sess_list, next_sess, sess)
        tgf_sess_remove(sess);
}

tgf_sess_t *tgf_sess_find_by_psi(tgf_ue_t *tgf_ue, uint8_t psi)
{
    tgf_sess_t *sess = NULL;

    ogs_list_for_each(&tgf_ue->sess_list, sess)
        if (psi == sess->psi) return sess;

    return NULL;
}

tgf_ue_t *tgf_ue_cycle(tgf_ue_t *tgf_ue)
{
    return ogs_pool_cycle(&tgf_ue_pool, tgf_ue);
}

tgf_sess_t *tgf_sess_cycle(tgf_sess_t *sess)
{
    return ogs_pool_cycle(&tgf_sess_pool, sess);
}

tgf_sdm_subscription_t *tgf_sdm_subscription_add(tgf_ue_t *tgf_ue)
{
    tgf_sdm_subscription_t *sdm_subscription = NULL;

    char id[OGS_UUID_FORMATTED_LENGTH + 1];
    ogs_uuid_t uuid;

    ogs_assert(tgf_ue);

    ogs_uuid_get(&uuid);
    ogs_uuid_format(id, &uuid);

    ogs_pool_alloc(&tgf_sdm_subscription_pool, &sdm_subscription);
    if (!sdm_subscription) {
        ogs_error("Maximum number of SDM Subscriptions [%d] reached",
                    max_num_of_tgf_sdm_subscriptions);
        return NULL;
    }
    memset(sdm_subscription, 0, sizeof *sdm_subscription);

    sdm_subscription->id = ogs_strdup(id);
    if (!sdm_subscription->id) {
        ogs_error("No memory for sdm_subscription->id [%s]", tgf_ue->suci);
        ogs_pool_free(&tgf_sdm_subscription_pool, sdm_subscription);
        return NULL;
    }

    sdm_subscription->tgf_ue = tgf_ue;

    ogs_hash_set(self.sdm_subscription_id_hash, sdm_subscription->id,
            strlen(sdm_subscription->id), sdm_subscription);

    ogs_list_add(&tgf_ue->sdm_subscription_list, sdm_subscription);

    return sdm_subscription;
}

void tgf_sdm_subscription_remove(tgf_sdm_subscription_t *sdm_subscription)
{
    ogs_assert(sdm_subscription);
    ogs_assert(sdm_subscription->tgf_ue);

    ogs_list_remove(&sdm_subscription->tgf_ue->sdm_subscription_list,
            sdm_subscription);

    ogs_assert(sdm_subscription->id);
    ogs_hash_set(self.sdm_subscription_id_hash, sdm_subscription->id, 
            strlen(sdm_subscription->id), NULL);
    ogs_free(sdm_subscription->id);

    if (sdm_subscription->data_change_callback_uri)
        ogs_free(sdm_subscription->data_change_callback_uri);

    ogs_pool_free(&tgf_sdm_subscription_pool, sdm_subscription);
}

void tgf_sdm_subscription_remove_all(tgf_ue_t *tgf_ue)
{
    tgf_sdm_subscription_t *sdm_subscription = NULL,
            *next_sdm_subscription = NULL;

    ogs_assert(tgf_ue);

    ogs_list_for_each_safe(&tgf_ue->sdm_subscription_list,
            next_sdm_subscription, sdm_subscription)
        tgf_sdm_subscription_remove(sdm_subscription);
}

tgf_sdm_subscription_t *tgf_sdm_subscription_find_by_id(char *id)
{
    ogs_assert(id);
    return (tgf_sdm_subscription_t *)ogs_hash_get(self.sdm_subscription_id_hash,
            id, strlen(id));
}

int get_ue_load(void)
{
    return (((ogs_pool_size(&tgf_ue_pool) -
            ogs_pool_avail(&tgf_ue_pool)) * 100) /
            ogs_pool_size(&tgf_ue_pool));
}
