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

#ifndef LMF_CONTEXT_H
#define LMF_CONTEXT_H

#include "ogs-app.h"
#include "ogs-dbi.h"
#include "ogs-sbi.h"

#include "lmf-sm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __lmf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __lmf_log_domain

typedef struct lmf_context_s {
    ogs_list_t      lmf_ue_list;
    ogs_hash_t      *suti_hash;

} lmf_context_t;


void lmf_context_init(void);
void lmf_context_final(void);
lmf_context_t *lmf_self(void);

int lmf_context_parse_config(void);

struct lmf_ue_s {
    ogs_sbi_object_t sbi;
    char *suti;

};

ogs_sbi_request_t *lmf_npcf_am_policy_control_build_delete(lmf_ue_t *lmf_ue, void *data);
void func(char *suti);
int lmf_event(void);
lmf_ue_t *lmf_ue_add(char *suti);
void lmf_ue_remove(lmf_ue_t *lmf_ue);
void lmf_ue_remove_all(void);
lmf_ue_t *lmf_ue_find_by_suti(char *suti);

#ifdef __cplusplus
}
#endif

#endif /* LMF_CONTEXT_H */
