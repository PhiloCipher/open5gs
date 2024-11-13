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

static maf_context_t self;

int __maf_log_domain;

static int context_initialized = 0;

void maf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize MAF context */
    memset(&self, 0, sizeof(maf_context_t));

    ogs_log_install_domain(&__ogs_dbi_domain, "dbi", ogs_core()->log.level);
    ogs_log_install_domain(&__maf_log_domain, "maf", ogs_core()->log.level);

    context_initialized = 1;
}

void maf_context_final(void)
{
    ogs_assert(context_initialized == 1);

    context_initialized = 0;
}

maf_context_t *maf_self(void)
{
    return &self;
}

static int maf_context_prepare(void)
{
    return OGS_OK;
}

static int maf_context_validation(void)
{
    return OGS_OK;
}

int maf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;
    int idx = 0;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = maf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if ((!strcmp(root_key, "maf")) &&
            (idx++ == ogs_app()->config_section_id)) {
            ogs_yaml_iter_t maf_iter;
            ogs_yaml_iter_recurse(&root_iter, &maf_iter);
            while (ogs_yaml_iter_next(&maf_iter)) {
                const char *maf_key = ogs_yaml_iter_key(&maf_iter);
                ogs_assert(maf_key);
                if (!strcmp(maf_key, "default")) {
                    /* handle config in sbi library */
                } else if (!strcmp(maf_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(maf_key, "nrf")) {
                    /* handle config in sbi library */
                } else if (!strcmp(maf_key, "scp")) {
                    /* handle config in sbi library */
                } else if (!strcmp(maf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(maf_key, "discovery")) {
                    /* handle config in sbi library */
                } else
                    ogs_warn("unknown key `%s`", maf_key);
            }
        }
    }

    rv = maf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}
