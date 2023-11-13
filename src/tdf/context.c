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
#include "nudm-build.h"
#include "nausf-build.h"
#include "nsmf-build.h"

static tdf_context_t self;

int __tdf_log_domain;

static int context_initialized = 0;
static OGS_POOL(tdf_ue_pool, tdf_ue_t);    
static OGS_POOL(ausf_ue_pool, ausf_ue_t);    
static OGS_POOL(udm_ue_pool, udm_ue_t);    
static OGS_POOL(smf_ue_pool, smf_ue_t);    

void tdf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize TDF context */
    memset(&self, 0, sizeof(tdf_context_t));

    ogs_log_install_domain(&__ogs_dbi_domain, "dbi", ogs_core()->log.level); // without this, sm wont start.
    ogs_log_install_domain(&__tdf_log_domain, "tdf", ogs_core()->log.level);
    ogs_pool_init(&tdf_ue_pool, ogs_app()->max.ue);
    ogs_pool_init(&ausf_ue_pool, ogs_app()->max.ue);
    ogs_pool_init(&udm_ue_pool, ogs_app()->max.ue);
    ogs_pool_init(&smf_ue_pool, ogs_app()->max.ue);

    ogs_list_init(&self.tdf_ue_list);
    self.suti_hash = ogs_hash_make();
    ogs_assert(self.suti_hash);

    context_initialized = 1;
}

void tdf_context_final(void)
{
    ogs_assert(context_initialized == 1);
    
    tdf_ue_remove_all();

    ogs_assert(self.suti_hash);
    ogs_hash_destroy(self.suti_hash);

    ogs_pool_final(&tdf_ue_pool);

    context_initialized = 0;
}

tdf_context_t *tdf_self(void)
{
    return &self;
}

static int tdf_context_prepare(void)
{
    return OGS_OK;
}

static int tdf_context_validation(void)
{
    return OGS_OK;
}

int tdf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = tdf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "tdf")) {
            ogs_yaml_iter_t tdf_iter;
            ogs_yaml_iter_recurse(&root_iter, &tdf_iter);
            while (ogs_yaml_iter_next(&tdf_iter)) {
                const char *tdf_key = ogs_yaml_iter_key(&tdf_iter);
                ogs_assert(tdf_key);
                if (!strcmp(tdf_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tdf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tdf_key, "discovery")) {
                    /* handle config in sbi library */
                } else
                    ogs_warn("unknown key `%s`", tdf_key);
            }
        }
    }

    rv = tdf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}


ogs_sbi_request_t *tdf_npcf_am_policy_control_build_delete(
        tdf_ue_t *tdf_ue, void *data)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;

    ogs_assert(tdf_ue);
    ogs_assert(tdf_ue->suti);

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_DELETE;
    message.h.service.name =
        (char *)OGS_SBI_SERVICE_NAME_NPCF_AM_POLICY_CONTROL;
    message.h.api.version = (char *)OGS_SBI_API_V1;
    message.h.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_POLICIES;
    
    request = ogs_sbi_build_request(&message);
    ogs_com("SENDING at %s: %d", OpenAPI_nf_type_ToString(NF_INSTANCE_TYPE(ogs_sbi_self()->nf_instance)), (int)request->http.content_length);
    ogs_com("Content Start:%sContent Stop",request->h.service.name);
    ogs_expect(request);

    return request;
}


void func(char* suti){

    //ogs_msleep(1000);
    //OGS_SBI_SERVICE_TYPE_NNEF_EVENTEXPOSURE
    tdf_ue_t* tdf_ue = tdf_ue_find_by_suti(
                       suti);

    if (!tdf_ue) {
        tdf_ue = tdf_ue_add(suti);
        ogs_assert(tdf_ue);
        }
    // ogs_pool_alloc(&tdf_ue_pool, &tdf_ue);
    // ogs_assert(tdf_ue);
    // //char *supi = "0000203190";
    // //tdf_ue->suti = ogs_strdup("imsi-999700000021309");
    // tdf_ue->suti = ogs_strdup(suti);
    // ogs_assert(tdf_ue->suti);
    // //ogs_hash_set(self.supi_hash, tdf_ue->supi, strlen(tdf_ue->supi), tdf_ue);
    // //ogs_sbi_request_t *request2 = tdf_npcf_am_policy_control_build_delete(tdf_ue,NULL);

    tdf_ue_sbi_discover_and_send(
    OGS_SBI_SERVICE_TYPE_NUDM_REPORT,
    NULL,
    tdf_nudm_report_build_ue_info,
    tdf_ue, 0, NULL);

    tdf_ue_sbi_discover_and_send(
    OGS_SBI_SERVICE_TYPE_NAUSF_REPORT,
    NULL,
    tdf_nausf_report_build_ue_info,
    tdf_ue, 0, NULL);

    tdf_ue_sbi_discover_and_send(
    OGS_SBI_SERVICE_TYPE_NSMF_REPORT,
    NULL,
    tdf_nsmf_report_build_ue_info,
    tdf_ue, 0, NULL);

    tdf_ue_sbi_discover_and_send(
    OGS_SBI_SERVICE_TYPE_NLMF_LOC,
    NULL,
    tdf_nlmf_location_build_determine_location,
    tdf_ue, 0, NULL);
}



int tdf_event()
{
    int rv;
    tdf_event_t *e = NULL;

    e = tdf_event_new(6);
    ogs_assert(e);
    //e->pkbuf = esmbuf;
    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_event_free(e);
    }

    return rv;
}


ausf_ue_t *ausf_ue_add()
{
    ausf_ue_t *ausf_ue = NULL;

    ogs_pool_alloc(&ausf_ue_pool, &ausf_ue);
    ogs_assert(ausf_ue);
    memset(ausf_ue, 0, sizeof *ausf_ue);

    //ogs_list_add(&self.ausf_ue_list, ausf_ue);

    return ausf_ue;
}

static smf_ue_t *smf_ue_add(void)
{
    smf_ue_t *smf_ue = NULL;

    ogs_pool_alloc(&smf_ue_pool, &smf_ue);
    if (!smf_ue) {
        ogs_error("Maximum number of smf_ue[%lld] reached",
                    (long long)ogs_app()->max.ue);
        return NULL;
    }
    memset(smf_ue, 0, sizeof *smf_ue);

    ogs_list_init(&smf_ue->sess_list);

    ogs_list_init(&smf_ue->loc_list);

    // ogs_list_add(&self.smf_ue_list, smf_ue);

    // smf_metrics_inst_global_inc(SMF_METR_GLOB_GAUGE_UES_ACTIVE);
    // ogs_info("[Added] Number of SMF-UEs is now %d",
    //         ogs_list_count(&self.smf_ue_list));
    return smf_ue;
}

udm_ue_t *udm_ue_add()
{
    udm_ue_t *udm_ue = NULL;

    ogs_pool_alloc(&udm_ue_pool, &udm_ue);
    ogs_assert(udm_ue);
    memset(udm_ue, 0, sizeof *udm_ue);

    //ogs_list_add(&self.ausf_ue_list, ausf_ue);

    return udm_ue;
}

tdf_ue_t *tdf_ue_add(char *suti)
{
    ogs_tmp("tdf_ue_add");
    tdf_ue_t *tdf_ue = NULL;

    ogs_assert(suti);

    ogs_pool_alloc(&tdf_ue_pool, &tdf_ue);
    ogs_assert(tdf_ue);
    memset(tdf_ue, 0, sizeof *tdf_ue);
    tdf_ue->ausf_ue= ausf_ue_add();
    tdf_ue->udm_ue= udm_ue_add();
    tdf_ue->smf_ue= smf_ue_add();

    // tdf_ue->ctx_id = ogs_msprintf("%d",
    //         (int)ogs_pool_index(&tdf_ue_pool, tdf_ue));
    // ogs_assert(tdf_ue->ctx_id);

    tdf_ue->suti = ogs_strdup(suti);
    ogs_assert(tdf_ue->suti);
    ogs_hash_set(self.suti_hash, tdf_ue->suti, strlen(tdf_ue->suti), tdf_ue);

    ogs_list_add(&self.tdf_ue_list, tdf_ue);

    return tdf_ue;
}


void tdf_ue_remove(tdf_ue_t *tdf_ue)
{
    ogs_assert(tdf_ue);

    ogs_list_remove(&self.tdf_ue_list, tdf_ue);

    /* Free SBI object memory */
    //ogs_sbi_object_free(&tdf_ue->sbi);


    // ogs_assert(tdf_ue->ctx_id);
    // ogs_free(tdf_ue->ctx_id);

    ogs_assert(tdf_ue->suti);
    ogs_hash_set(self.suti_hash, tdf_ue->suti, strlen(tdf_ue->suti), NULL);
    ogs_free(tdf_ue->suti);


    //if (tdf_ue->serving_network_name)
    //    ogs_free(tdf_ue->serving_network_name);


    ogs_pool_free(&tdf_ue_pool, tdf_ue);
}

void tdf_ue_remove_all(void)
{
    tdf_ue_t *tdf_ue = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.tdf_ue_list, next, tdf_ue)
        tdf_ue_remove(tdf_ue);
}

tdf_ue_t *tdf_ue_find_by_suti(char *suti)
{
    ogs_assert(suti);
    return (tdf_ue_t *)ogs_hash_get(self.suti_hash, suti, strlen(suti));
}