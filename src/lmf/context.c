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


static lmf_context_t self;

int __lmf_log_domain;

static int context_initialized = 0;
static OGS_POOL(lmf_ue_pool, lmf_ue_t);     

void lmf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize LMF context */
    memset(&self, 0, sizeof(lmf_context_t));

    ogs_log_install_domain(&__ogs_dbi_domain, "dbi", ogs_core()->log.level); // without this, sm wont start.
    ogs_log_install_domain(&__lmf_log_domain, "lmf", ogs_core()->log.level);
    ogs_pool_init(&lmf_ue_pool, ogs_app()->max.ue);

    ogs_list_init(&self.lmf_ue_list);
    self.suti_hash = ogs_hash_make();
    ogs_assert(self.suti_hash);

    context_initialized = 1;
}

void lmf_context_final(void)
{
    ogs_assert(context_initialized == 1);
    
    lmf_ue_remove_all();

    ogs_assert(self.suti_hash);
    ogs_hash_destroy(self.suti_hash);

    ogs_pool_final(&lmf_ue_pool);

    context_initialized = 0;
}

lmf_context_t *lmf_self(void)
{
    return &self;
}

static int lmf_context_prepare(void)
{
    return OGS_OK;
}

static int lmf_context_validation(void)
{
    return OGS_OK;
}

int lmf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = lmf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "lmf")) {
            ogs_yaml_iter_t lmf_iter;
            ogs_yaml_iter_recurse(&root_iter, &lmf_iter);
            while (ogs_yaml_iter_next(&lmf_iter)) {
                const char *lmf_key = ogs_yaml_iter_key(&lmf_iter);
                ogs_assert(lmf_key);
                if (!strcmp(lmf_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(lmf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(lmf_key, "discovery")) {
                    /* handle config in sbi library */
                } else
                    ogs_warn("unknown key `%s`", lmf_key);
            }
        }
    }

    rv = lmf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}


ogs_sbi_request_t *lmf_npcf_am_policy_control_build_delete(
        lmf_ue_t *lmf_ue, void *data)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;

    ogs_assert(lmf_ue);
    ogs_assert(lmf_ue->suti);

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
    lmf_ue_t* lmf_ue = lmf_ue_find_by_suti(
                       suti);

    if (!lmf_ue) {
        lmf_ue = lmf_ue_add(suti);
        ogs_assert(lmf_ue);
        }

}



int lmf_event()
{
    int rv;
    lmf_event_t *e = NULL;

    e = lmf_event_new(6);
    ogs_assert(e);
    //e->pkbuf = esmbuf;
    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_event_free(e);
    }

    return rv;
}


lmf_ue_t *lmf_ue_add(char *suti)
{
    ogs_tmp("lmf_ue_add");
    lmf_ue_t *lmf_ue = NULL;

    ogs_assert(suti);

    ogs_pool_alloc(&lmf_ue_pool, &lmf_ue);
    ogs_assert(lmf_ue);
    memset(lmf_ue, 0, sizeof *lmf_ue);
    
    // lmf_ue->ctx_id = ogs_msprintf("%d",
    //         (int)ogs_pool_index(&lmf_ue_pool, lmf_ue));
    // ogs_assert(lmf_ue->ctx_id);

    lmf_ue->suti = ogs_strdup(suti);
    ogs_assert(lmf_ue->suti);
    ogs_hash_set(self.suti_hash, lmf_ue->suti, strlen(lmf_ue->suti), lmf_ue);

    ogs_list_add(&self.lmf_ue_list, lmf_ue);

    return lmf_ue;
}


void lmf_ue_remove(lmf_ue_t *lmf_ue)
{
    ogs_assert(lmf_ue);

    ogs_list_remove(&self.lmf_ue_list, lmf_ue);

    /* Free SBI object memory */
    //ogs_sbi_object_free(&lmf_ue->sbi);


    // ogs_assert(lmf_ue->ctx_id);
    // ogs_free(lmf_ue->ctx_id);

    ogs_assert(lmf_ue->suti);
    ogs_hash_set(self.suti_hash, lmf_ue->suti, strlen(lmf_ue->suti), NULL);
    ogs_free(lmf_ue->suti);


    //if (lmf_ue->serving_network_name)
    //    ogs_free(lmf_ue->serving_network_name);


    ogs_pool_free(&lmf_ue_pool, lmf_ue);
}

void lmf_ue_remove_all(void)
{
    lmf_ue_t *lmf_ue = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.lmf_ue_list, next, lmf_ue)
        lmf_ue_remove(lmf_ue);
}

lmf_ue_t *lmf_ue_find_by_suti(char *suti)
{
    ogs_assert(suti);
    return (lmf_ue_t *)ogs_hash_get(self.suti_hash, suti, strlen(suti));
}