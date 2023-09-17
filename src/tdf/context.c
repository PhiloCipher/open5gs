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

static tdf_context_t self;

int __tdf_log_domain;

static int context_initialized = 0;

void tdf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize TDF context */
    memset(&self, 0, sizeof(tdf_context_t));

    ogs_log_install_domain(&__ogs_dbi_domain, "dbi", ogs_core()->log.level);
    ogs_log_install_domain(&__tdf_log_domain, "tdf", ogs_core()->log.level);

    context_initialized = 1;
}

void tdf_context_final(void)
{
    ogs_assert(context_initialized == 1);

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
